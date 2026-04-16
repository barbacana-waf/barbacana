package crs

import "embed"

//go:embed rules/*.conf rules/*.data crs-setup.conf
var FS embed.FS
