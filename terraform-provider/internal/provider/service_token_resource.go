package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

var _ resource.Resource = (*serviceTokenResource)(nil)
var _ resource.ResourceWithConfigure = (*serviceTokenResource)(nil)
var _ resource.ResourceWithImportState = (*serviceTokenResource)(nil)

type serviceTokenResource struct {
	api *client.Client
}

type serviceTokenModel struct {
	ID    types.String `tfsdk:"id"`
	AppID types.String `tfsdk:"app_id"`
	Name  types.String `tfsdk:"name"`
	EnvID types.String `tfsdk:"env_id"`
	Token types.String `tfsdk:"token"`
}

func NewServiceTokenResource() resource.Resource { return &serviceTokenResource{} }

func (r *serviceTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_token"
}

func (r *serviceTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.api = apiFrom(req.ProviderData)
}

func (r *serviceTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A service token for an app, optionally scoped to one environment. The token value is shown once at creation; an imported token keeps an empty value.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"app_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"env_id": schema.StringAttribute{
				Optional:      true,
				Description:   "Scope the token to one environment.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"token": schema.StringAttribute{
				Computed:      true,
				Sensitive:     true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *serviceTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	env, _ := knownString(plan.EnvID)
	created, err := r.api.CreateToken(ctx, plan.AppID.ValueString(), plan.Name.ValueString(), env)
	if err != nil {
		resp.Diagnostics.AddError("Could not create service token", err.Error())
		return
	}
	plan.ID = types.StringValue(created.ID)
	plan.Token = types.StringValue(created.Token)
	if plan.EnvID.IsNull() || plan.EnvID.IsUnknown() {
		plan.EnvID = types.StringValue("")
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	token, found, err := findToken(ctx, r.api, state.AppID.ValueString(), state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read service token", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(token.ID)
	state.AppID = types.StringValue(token.AppID)
	state.Name = types.StringValue(token.Name)
	state.EnvID = types.StringValue(token.EnvID)
	// The plaintext token is never returned again; keep the value already in
	// state (empty after an import).
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceTokenResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Service tokens cannot be updated", "Change app_id, name or env_id and Terraform will replace the token")
}

func (r *serviceTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.api.RevokeToken(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not revoke service token", err.Error())
	}
}

func (r *serviceTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func findToken(ctx context.Context, api *client.Client, app, id string) (client.ServiceToken, bool, error) {
	apps := []string{app}
	if app == "" {
		orgs, err := api.ListOrgs(ctx)
		if err != nil {
			return client.ServiceToken{}, false, err
		}
		apps = apps[:0]
		for _, org := range orgs {
			list, err := api.ListApps(ctx, org.ID)
			if err != nil {
				return client.ServiceToken{}, false, err
			}
			for _, item := range list {
				apps = append(apps, item.ID)
			}
		}
	}
	for _, a := range apps {
		tokens, err := api.ListTokens(ctx, a)
		if err != nil {
			return client.ServiceToken{}, false, err
		}
		for _, token := range tokens {
			if token.ID == id {
				return token, true, nil
			}
		}
	}
	return client.ServiceToken{}, false, nil
}
