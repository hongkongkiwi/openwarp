package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

var _ datasource.DataSource = (*secretDataSource)(nil)
var _ datasource.DataSourceWithConfigure = (*secretDataSource)(nil)

type secretDataSource struct {
	api *client.Client
}

type secretDataModel struct {
	ID      types.String `tfsdk:"id"`
	EnvID   types.String `tfsdk:"env_id"`
	Key     types.String `tfsdk:"key"`
	Path    types.String `tfsdk:"path"`
	Value   types.String `tfsdk:"value"`
	Type    types.String `tfsdk:"type"`
	Version types.Int64  `tfsdk:"version"`
}

func NewSecretDataSource() datasource.DataSource { return &secretDataSource{} }

func (d *secretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *secretDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	d.api = apiFrom(req.ProviderData)
}

func (d *secretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Read a secret by key and path.",
		Attributes: map[string]schema.Attribute{
			"id":      schema.StringAttribute{Computed: true},
			"env_id":  schema.StringAttribute{Required: true},
			"key":     schema.StringAttribute{Required: true, Description: "Secret name, matched case-insensitively."},
			"path":    schema.StringAttribute{Optional: true, Description: "'/' by default."},
			"value":   schema.StringAttribute{Computed: true, Sensitive: true},
			"type":    schema.StringAttribute{Computed: true},
			"version": schema.Int64Attribute{Computed: true},
		},
	}
}

func (d *secretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config secretDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secret, found, err := findSecret(ctx, d.api, config.EnvID.ValueString(), config.Key.ValueString(), config.Path.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read secret", err.Error())
		return
	}
	if !found {
		resp.Diagnostics.AddError("Secret not found", fmt.Sprintf("No secret %s on path %s in environment %s", config.Key.ValueString(), config.Path.ValueString(), config.EnvID.ValueString()))
		return
	}
	if secret.Type == "sealed" || secret.Value == nil {
		resp.Diagnostics.AddError("Secret is sealed", "A sealed secret has no readable value")
		return
	}
	config.ID = types.StringValue(secret.ID)
	config.Key = types.StringValue(secret.Key)
	config.Path = types.StringValue(secret.Path)
	config.Value = types.StringValue(*secret.Value)
	config.Type = types.StringValue(secret.Type)
	config.Version = types.Int64Value(secret.Version)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
