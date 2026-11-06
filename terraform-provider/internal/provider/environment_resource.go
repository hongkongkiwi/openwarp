package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

var _ resource.Resource = (*environmentResource)(nil)
var _ resource.ResourceWithConfigure = (*environmentResource)(nil)
var _ resource.ResourceWithImportState = (*environmentResource)(nil)

type environmentResource struct {
	api *client.Client
}

type environmentModel struct {
	ID              types.String `tfsdk:"id"`
	AppID           types.String `tfsdk:"app_id"`
	Name            types.String `tfsdk:"name"`
	Restricted      types.Bool   `tfsdk:"restricted"`
	RequireApproval types.Bool   `tfsdk:"require_approval"`
}

func NewEnvironmentResource() resource.Resource { return &environmentResource{} }

func (r *environmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (r *environmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.api = apiFrom(req.ProviderData)
}

func (r *environmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An environment inside an app. Restricting it limits access to its members; requiring approval makes direct deploys admin-only.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"app_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{Required: true},
			"restricted": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Only environment members (and admins) may read or write.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"require_approval": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Direct deploys require an admin; other members submit proposals.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *environmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.api.CreateEnv(ctx, plan.AppID.ValueString(), plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not create environment", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	restricted, approval := boolPointer(plan.Restricted), boolPointer(plan.RequireApproval)
	if restricted != nil || approval != nil {
		if err := r.api.SetEnvPolicy(ctx, id, restricted, approval); err != nil {
			resp.Diagnostics.AddError("Could not set environment policy", err.Error())
			return
		}
	}
	if plan.Restricted.IsNull() || plan.Restricted.IsUnknown() {
		plan.Restricted = types.BoolValue(false)
	}
	if plan.RequireApproval.IsNull() || plan.RequireApproval.IsUnknown() {
		plan.RequireApproval = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *environmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	env, found, err := findEnv(ctx, r.api, state.AppID.ValueString(), state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read environment", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(env.ID)
	state.AppID = types.StringValue(env.AppID)
	state.Name = types.StringValue(env.Name)
	state.Restricted = types.BoolValue(env.Restricted == 1)
	state.RequireApproval = types.BoolValue(env.RequireApproval == 1)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *environmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Name.ValueString() != state.Name.ValueString() {
		if err := r.api.RenameEnv(ctx, state.ID.ValueString(), plan.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("Could not rename environment", err.Error())
			return
		}
	}
	if !plan.Restricted.Equal(state.Restricted) || !plan.RequireApproval.Equal(state.RequireApproval) {
		if err := r.api.SetEnvPolicy(ctx, state.ID.ValueString(), boolPointer(plan.Restricted), boolPointer(plan.RequireApproval)); err != nil {
			resp.Diagnostics.AddError("Could not update environment policy", err.Error())
			return
		}
	}
	plan.ID = state.ID
	if plan.Restricted.IsNull() || plan.Restricted.IsUnknown() {
		plan.Restricted = types.BoolValue(false)
	}
	if plan.RequireApproval.IsNull() || plan.RequireApproval.IsUnknown() {
		plan.RequireApproval = types.BoolValue(false)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *environmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.api.DeleteEnv(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete environment", err.Error())
	}
}

func (r *environmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func findEnv(ctx context.Context, api *client.Client, app, id string) (client.Env, bool, error) {
	apps := []string{app}
	if app == "" {
		orgs, err := api.ListOrgs(ctx)
		if err != nil {
			return client.Env{}, false, err
		}
		apps = apps[:0]
		for _, org := range orgs {
			list, err := api.ListApps(ctx, org.ID)
			if err != nil {
				return client.Env{}, false, err
			}
			for _, item := range list {
				apps = append(apps, item.ID)
			}
		}
	}
	for _, a := range apps {
		envs, err := api.ListEnvs(ctx, a)
		if err != nil {
			return client.Env{}, false, err
		}
		for _, env := range envs {
			if env.ID == id {
				return env, true, nil
			}
		}
	}
	return client.Env{}, false, nil
}
