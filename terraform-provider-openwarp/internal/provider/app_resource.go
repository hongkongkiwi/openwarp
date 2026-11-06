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

var _ resource.Resource = (*appResource)(nil)
var _ resource.ResourceWithConfigure = (*appResource)(nil)
var _ resource.ResourceWithImportState = (*appResource)(nil)

type appResource struct {
	api *client.Client
}

type appModel struct {
	ID    types.String `tfsdk:"id"`
	OrgID types.String `tfsdk:"org_id"`
	Name  types.String `tfsdk:"name"`
}

func NewAppResource() resource.Resource { return &appResource{} }

func (r *appResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app"
}

func (r *appResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.api = apiFrom(req.ProviderData)
}

func (r *appResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An application inside an organisation. Creating one also creates the Development, Staging and Production environments.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"org_id": schema.StringAttribute{
				Required:      true,
				Description:   "Organisation that owns the app.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Display name.",
			},
		},
	}
}

func (r *appResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan appModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id, err := r.api.CreateApp(ctx, plan.OrgID.ValueString(), plan.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not create app", err.Error())
		return
	}
	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *appResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state appModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	app, found, err := findApp(ctx, r.api, state.OrgID.ValueString(), state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read app", err.Error())
		return
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(app.ID)
	state.OrgID = types.StringValue(app.OrgID)
	state.Name = types.StringValue(app.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *appResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state appModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.Name.ValueString() != state.Name.ValueString() {
		if err := r.api.RenameApp(ctx, state.ID.ValueString(), plan.Name.ValueString()); err != nil {
			resp.Diagnostics.AddError("Could not rename app", err.Error())
			return
		}
	}
	plan.ID = state.ID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *appResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state appModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.api.DeleteApp(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete app", err.Error())
	}
}

func (r *appResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// findApp locates an app by id. When the organisation is unknown (import), it
// scans the caller's organisations.
func findApp(ctx context.Context, api *client.Client, org, id string) (client.App, bool, error) {
	orgs := []string{org}
	if org == "" {
		list, err := api.ListOrgs(ctx)
		if err != nil {
			return client.App{}, false, err
		}
		orgs = orgs[:0]
		for _, item := range list {
			orgs = append(orgs, item.ID)
		}
	}
	for _, o := range orgs {
		apps, err := api.ListApps(ctx, o)
		if err != nil {
			return client.App{}, false, err
		}
		for _, app := range apps {
			if app.ID == id {
				return app, true, nil
			}
		}
	}
	return client.App{}, false, nil
}
