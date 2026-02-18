// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/networkops/terraform-provider-networkops/internal/datasources"
	"github.com/networkops/terraform-provider-networkops/internal/resources"
)

// Ensure NetworkOpsProvider satisfies various provider interfaces.
var _ provider.Provider = &NetworkOpsProvider{}

// NetworkOpsProvider defines the provider implementation.
type NetworkOpsProvider struct {
	version string
}

// NetworkOpsProviderModel describes the provider data model.
type NetworkOpsProviderModel struct {
	APIURL   types.String `tfsdk:"api_url"`
	Token    types.String `tfsdk:"token"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	Timeout  types.Int64  `tfsdk:"timeout"`
}

// New creates a new provider instance.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &NetworkOpsProvider{
			version: version,
		}
	}
}

// Metadata returns the provider type name.
func (p *NetworkOpsProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "networkops"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *NetworkOpsProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The NetworkOps provider enables infrastructure-as-code management of network devices.",
		MarkdownDescription: `
The NetworkOps provider enables infrastructure-as-code management of network devices through the NetworkOps API.

## Features

- **Device Management**: Read device inventory, health status, and interface information
- **Configuration**: Apply configuration changes to network devices declaratively
- **Backups**: Create and manage configuration backups
- **Topology**: Query network topology and routing information

## Authentication

The provider supports two authentication methods:

1. **JWT Token**: Use a pre-generated JWT token (recommended for CI/CD)
2. **Username/Password**: Authenticate with credentials to obtain a token

## Example Usage

` + "```hcl" + `
provider "networkops" {
  api_url = "http://localhost:5001"
  token   = var.networkops_token
}
` + "```" + `
`,
		Attributes: map[string]schema.Attribute{
			"api_url": schema.StringAttribute{
				Description:         "The NetworkOps API URL. Can also be set via NETWORKOPS_API_URL environment variable.",
				MarkdownDescription: "The NetworkOps API URL. Can also be set via `NETWORKOPS_API_URL` environment variable.",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				Description:         "JWT authentication token. Can also be set via NETWORKOPS_TOKEN environment variable.",
				MarkdownDescription: "JWT authentication token. Can also be set via `NETWORKOPS_TOKEN` environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
			"username": schema.StringAttribute{
				Description:         "Username for authentication (alternative to token). Can also be set via NETWORKOPS_USERNAME.",
				MarkdownDescription: "Username for authentication (alternative to token). Can also be set via `NETWORKOPS_USERNAME`.",
				Optional:            true,
			},
			"password": schema.StringAttribute{
				Description:         "Password for authentication (used with username). Can also be set via NETWORKOPS_PASSWORD.",
				MarkdownDescription: "Password for authentication (used with username). Can also be set via `NETWORKOPS_PASSWORD`.",
				Optional:            true,
				Sensitive:           true,
			},
			"timeout": schema.Int64Attribute{
				Description:         "API request timeout in seconds. Defaults to 30.",
				MarkdownDescription: "API request timeout in seconds. Defaults to `30`.",
				Optional:            true,
			},
		},
	}
}

// Configure prepares a NetworkOps API client for data sources and resources.
func (p *NetworkOpsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	tflog.Info(ctx, "Configuring NetworkOps provider")

	var config NetworkOpsProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check for unknown values
	if config.APIURL.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("api_url"),
			"Unknown NetworkOps API URL",
			"The provider cannot create the NetworkOps API client as there is an unknown configuration value for the API URL.",
		)
	}
	if config.Token.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("token"),
			"Unknown NetworkOps Token",
			"The provider cannot create the NetworkOps API client as there is an unknown configuration value for the token.",
		)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Use environment variables as defaults
	apiURL := os.Getenv("NETWORKOPS_API_URL")
	token := os.Getenv("NETWORKOPS_TOKEN")
	username := os.Getenv("NETWORKOPS_USERNAME")
	password := os.Getenv("NETWORKOPS_PASSWORD")

	// Override with config values if set
	if !config.APIURL.IsNull() {
		apiURL = config.APIURL.ValueString()
	}
	if !config.Token.IsNull() {
		token = config.Token.ValueString()
	}
	if !config.Username.IsNull() {
		username = config.Username.ValueString()
	}
	if !config.Password.IsNull() {
		password = config.Password.ValueString()
	}

	// Default API URL
	if apiURL == "" {
		apiURL = "http://localhost:5001"
	}

	// Validate authentication
	if token == "" && (username == "" || password == "") {
		resp.Diagnostics.AddError(
			"Missing Authentication",
			"Either 'token' or both 'username' and 'password' must be provided. "+
				"Set via provider configuration or environment variables (NETWORKOPS_TOKEN, NETWORKOPS_USERNAME, NETWORKOPS_PASSWORD).",
		)
		return
	}

	// Determine timeout
	timeout := int64(30)
	if !config.Timeout.IsNull() {
		timeout = config.Timeout.ValueInt64()
	}

	// Create API client
	client, err := NewClient(apiURL, token, username, password, timeout)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to Create NetworkOps Client",
			"An unexpected error occurred when creating the NetworkOps API client. "+
				"Error: "+err.Error(),
		)
		return
	}

	// If using username/password, authenticate to get token
	if token == "" && username != "" {
		err = client.Authenticate(ctx)
		if err != nil {
			resp.Diagnostics.AddError(
				"Authentication Failed",
				"Failed to authenticate with NetworkOps API using provided credentials. "+
					"Error: "+err.Error(),
			)
			return
		}
	}

	// Verify connectivity
	err = client.HealthCheck(ctx)
	if err != nil {
		resp.Diagnostics.AddWarning(
			"NetworkOps API Health Check Failed",
			"The API health check failed. Some operations may not work. "+
				"Error: "+err.Error(),
		)
	}

	tflog.Info(ctx, "Configured NetworkOps provider", map[string]interface{}{
		"api_url": apiURL,
	})

	// Make client available to data sources and resources
	resp.DataSourceData = client
	resp.ResourceData = client
}

// Resources defines the resources implemented in the provider.
func (p *NetworkOpsProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		resources.NewDeviceConfigResource,
		resources.NewInterfaceResource,
		resources.NewBackupResource,
	}
}

// DataSources defines the data sources implemented in the provider.
func (p *NetworkOpsProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		datasources.NewDevicesDataSource,
		datasources.NewDeviceDataSource,
		datasources.NewHealthDataSource,
		datasources.NewTopologyDataSource,
		datasources.NewRoutingTableDataSource,
	}
}
