package config

import "strings"

// Config schema versions. VersionV1Beta1 is the current version;
// VersionV1Alpha1 is schema-identical and still accepted, but deprecated.
const (
	VersionV1Alpha1 = "v1alpha1"
	VersionV1Beta1  = "v1beta1"
)

// supportedVersions lists accepted versions, preferred first.
var supportedVersions = []string{VersionV1Beta1, VersionV1Alpha1}

func isSupportedVersion(v string) bool {
	for _, s := range supportedVersions {
		if v == s {
			return true
		}
	}
	return false
}

// supportedVersionsList renders the accepted versions for error messages.
func supportedVersionsList() string {
	q := make([]string, len(supportedVersions))
	for i, s := range supportedVersions {
		q[i] = `"` + s + `"`
	}
	return strings.Join(q, ", ")
}
