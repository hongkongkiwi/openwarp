package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/client"
)

func apiFrom(data any) *client.Client {
	api, _ := data.(*client.Client)
	return api
}

func knownString(value types.String) (string, bool) {
	if value.IsNull() || value.IsUnknown() {
		return "", false
	}
	return value.ValueString(), true
}

func knownBool(value types.Bool) (bool, bool) {
	if value.IsNull() || value.IsUnknown() {
		return false, false
	}
	return value.ValueBool(), true
}

func boolPointer(value types.Bool) *bool {
	if known, ok := knownBool(value); ok {
		return &known
	}
	return nil
}
