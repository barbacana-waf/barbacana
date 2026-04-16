package main

import (
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"

	_ "github.com/barbacana-waf/barbacana/internal/pipeline"
	_ "github.com/barbacana-waf/barbacana/internal/protections/crs"
	_ "github.com/barbacana-waf/barbacana/internal/protections/headers"
	_ "github.com/barbacana-waf/barbacana/internal/protections/openapi"
	_ "github.com/barbacana-waf/barbacana/internal/protections/protocol"
	_ "github.com/barbacana-waf/barbacana/internal/protections/request"

	"github.com/barbacana-waf/barbacana/cmd"
)

func main() {
	cmd.Execute()
}
