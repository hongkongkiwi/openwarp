package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

var _ resource.Resource = (*secretResource)(nil)
var _ resource.ResourceWithConfigure = (*secretResource)(nil)
var _ resource.ResourceWithImportState = (*secretResource)(nil)

var secretKeyPattern = regexp.MustCompile(`^[A-Z0-9_.-]{1,128}$`)

type secretResource struct {
	api *client.Client
}

type secretModel struct {
	ID      types.String `tfsdk:"id"`
	EnvID   types.String `tfsdk:"env_id"`
	Key     types.String `tfsdk:"key"`
	Value   types.String `tfsdk:"value"`
	Path    types.String `tfsdk:"path"`
	Type    types.String `tfsdk:"type"`
	Comment types.String `tfsdk:"comment"`
	Tags    types.String `tfsdk:"tags"`
	Version types.Int64  `tfsdk:"version"`
}

func NewSecretResource() resource.Resource { return &secretResource{} }

func (r *secretResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (r *secretResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.api = apiFrom(req.ProviderData)
}

func (r *secretResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A secret in an environment. Keys are stored upper case. Sealed secrets cannot be read back through the API, so this resource does not manage them.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"env_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"key": schema.StringAttribute{
				Required:      true,
				Description:   "Secret name. Use upper-case letters, digits, dot, dash and underscore; the API stores keys upper case.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{stringvalidator.RegexMatches(secretKeyPattern, "keys use upper-case letters, digits, dot, dash and underscore")},
			},
			"value": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
			},
			"path": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Secret path, '/' by default.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()},
			},
			"type": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "secret or config.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Validators:    []validator.String{stringvalidator.OneOf("secret", "config")},
			},
			"comment": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"tags": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"version": schema.Int64Attribute{Computed: true},
		},
	}
}

func (r *secretResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, err := r.deploy(ctx, &plan)
	if err != nil {
		resp.Diagnostics.AddError("Could not create secret", err.Error())
		return
	}
	applySecret(&plan, secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, found, err := findSecret(ctx, r.api, state.EnvID.ValueString(), state.Key.ValueString(), state.Path.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read secret", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	if secret.Type == "sealed" {
		resp.Diagnostics.AddError("Sealed secret is not readable", fmt.Sprintf("%s is sealed; the API never returns its value, so this provider cannot manage it", secret.Key))
		return
	}
	applySecret(&state, secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *secretResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan secretModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, err := r.deploy(ctx, &plan)
	if err != nil {
		resp.Diagnostics.AddError("Could not update secret", err.Error())
		return
	}
	applySecret(&plan, secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *secretResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state secretModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, found, err := findSecret(ctx, r.api, state.EnvID.ValueString(), state.Key.ValueString(), state.Path.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not look up secret", err.Error())
		return
	}
	if !found {
		return
	}
	if err := r.api.DeleteSecret(ctx, secret.ID); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete secret", err.Error())
	}
}

func (r *secretResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// env_id:key or env_id:path:key
	parts := strings.SplitN(req.ID, ":", 3)
	if len(parts) < 2 || parts[0] == "" || parts[len(parts)-1] == "" {
		resp.Diagnostics.AddError("Invalid import id", "Use env_id:key or env_id:path:key")
		return
	}
	env := parts[0]
	key := parts[len(parts)-1]
	secretPath := "/"
	if len(parts) == 3 {
		secretPath = parts[1]
	}
	resp.State.SetAttribute(ctx, path.Root("env_id"), env)
	resp.State.SetAttribute(ctx, path.Root("key"), strings.ToUpper(key))
	resp.State.SetAttribute(ctx, path.Root("path"), secretPath)
}

func (r *secretResource) deploy(ctx context.Context, plan *secretModel) (client.Secret, error) {
	key := strings.ToUpper(plan.Key.ValueString())
	secretPath := plan.Path.ValueString()
	if secretPath == "" {
		secretPath = "/"
	}
	secretType := plan.Type.ValueString()
	if secretType == "" {
		secretType = "secret"
	}
	if secretType == "sealed" {
		return client.Secret{}, fmt.Errorf("sealed secrets cannot be managed: the API never returns their value")
	}
	input := client.SecretInput{
		Key:     key,
		Value:   plan.Value.ValueString(),
		Path:    secretPath,
		Comment: plan.Comment.ValueString(),
		Tags:    plan.Tags.ValueString(),
		Type:    secretType,
	}
	if err := r.api.DeploySecret(ctx, plan.EnvID.ValueString(), input); err != nil {
		return client.Secret{}, err
	}
	secret, found, err := findSecret(ctx, r.api, plan.EnvID.ValueString(), key, secretPath)
	if err != nil {
		return client.Secret{}, err
	}
	if !found {
		return client.Secret{}, fmt.Errorf("secret %s was deployed but could not be read back", key)
	}
	return secret, nil
}

func applySecret(model *secretModel, secret client.Secret) {
	model.ID = types.StringValue(secret.ID)
	model.Key = types.StringValue(secret.Key)
	model.Path = types.StringValue(secret.Path)
	model.Type = types.StringValue(secret.Type)
	model.Comment = types.StringValue(secret.Comment)
	model.Tags = types.StringValue(secret.Tags)
	model.Version = types.Int64Value(secret.Version)
	if secret.Value != nil {
		model.Value = types.StringValue(*secret.Value)
	}
}

func findSecret(ctx context.Context, api *client.Client, env, key, secretPath string) (client.Secret, bool, error) {
	key = strings.ToUpper(key)
	if secretPath == "" {
		secretPath = "/"
	}
	secrets, err := api.ListSecrets(ctx, env)
	if err != nil {
		return client.Secret{}, false, err
	}
	for _, secret := range secrets {
		if secret.Key == key && secret.Path == secretPath {
			return secret, true, nil
		}
	}
	return client.Secret{}, false, nil
}
