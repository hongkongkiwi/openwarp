package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/hongkongkiwi/terraform-provider-openwarp/internal/provider"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with debugger support")
	flag.Parse()
	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/hongkongkiwi/openwarp",
		Debug:   debug,
	}
	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatalf("could not serve provider: %s", err)
	}
}
