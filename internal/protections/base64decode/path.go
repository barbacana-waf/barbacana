package base64decode

import (
	"strconv"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// scanPath walks the slash-separated segments of the normalized
// inspection path and emits a synthetic PATH arg for each segment
// whose contents decode as base64.
//
// Each successful decode counts toward the budget; the caller stops
// the walk when the budget is exceeded.
func scanPath(path string, ia *protections.InspectionArgs, budget *budget) {
	if path == "" || budget.exceeded() {
		return
	}
	idx := 0
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		decoded, ok := TryDecode(seg)
		if !ok {
			continue
		}
		if !budget.consume() {
			return
		}
		ia.PATH = append(ia.PATH, protections.ArgPair{
			Name:  "path.b64decoded." + strconv.Itoa(idx),
			Value: decoded,
		})
		idx++
	}
}
