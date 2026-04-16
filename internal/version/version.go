package version

// Populated via -ldflags at build time. See build.md.
var (
	Version    = "dev"
	Commit     = "unknown"
	CRSVersion = "unknown"
)

type Info struct {
	Version    string
	Commit     string
	CRSVersion string
	GoVersion  string
}
