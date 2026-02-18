// Copyright (c) 2025 NetworkOps
// SPDX-License-Identifier: MPL-2.0

// Terraform Provider for NetworkOps
//
// This provider enables infrastructure-as-code management of network devices
// through the NetworkOps API. It supports:
//   - Reading device inventory and health status
//   - Applying configuration changes to devices
//   - Managing interface settings
//   - Creating configuration backups
//
// Example usage:
//
//	terraform {
//	  required_providers {
//	    networkops = {
//	      source = "networkops/networkops"
//	    }
//	  }
//	}
//
//	provider "networkops" {
//	  api_url = "http://localhost:5001"
//	  token   = var.networkops_token
//	}

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/networkops/terraform-provider-networkops/internal/provider"
)

// Version is set during build via ldflags
var version = "dev"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/networkops/networkops",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		log.Fatal(err.Error())
	}
}
