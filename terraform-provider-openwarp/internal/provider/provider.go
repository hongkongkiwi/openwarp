package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

var _ provider.Provider = (*openwarpProvider)(nil)

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &openwarpProvider{version: version} }
}

type openwarpProvider struct {
	version string
}

type providerModel struct {
	Host  types.String `tfsdk:"host"`
	Token types.String `tfsdk:"token"`
}

func (p *openwarpProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "openwarp"
	resp.Version = p.version
}

func (p *openwarpProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage OpenWarp organisations, apps, environments, secrets and service tokens. " +
			"Configure the instance with `host` and `token`, or with `OPENWARP_HOST` and `OPENWARP_TOKEN`.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Optional:    true,
				Description: "Instance origin, for example https://secrets.example.com. Defaults to OPENWARP_HOST.",
			},
			"token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Session, service or OAuth access token. Defaults to OPENWARP_TOKEN.",
			},
		},
	}
}

func (p *openwarpProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	host := os.Getenv("OPENWARP_HOST")
	if !config.Host.IsNull() && !config.Host.IsUnknown() {
		host = config.Host.ValueString()
	}
	token := os.Getenv("OPENWARP_TOKEN")
	if !config.Token.IsNull() && !config.Token.IsUnknown() {
		token = config.Token.ValueString()
	}
	if host == "" {
		resp.Diagnostics.AddError("Missing OpenWarp host", "Set the provider's host argument or OPENWARP_HOST.")
		return
	}
	if token == "" {
		resp.Diagnostics.AddError("Missing OpenWarp token", "Set the provider's token argument or OPENWARP_TOKEN.")
		return
	}
	api := client.New(host, token)
	resp.ResourceData = api
	resp.DataSourceData = api
}

func (p *openwarpProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAppResource,
		NewEnvironmentResource,
		NewSecretResource,
		NewServiceTokenResource,
	}
}

func (p *openwarpProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewSecretDataSource}
}
