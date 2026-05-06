package base64decode

import (
	"net/url"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// scanQuery walks the query parameters in rawQuery and emits a
// synthetic GET arg for each value that decodes as base64.
//
// Multi-valued keys are walked element by element; each decoded value
// is emitted under the same synthetic name (Coraza handles multi-
// valued ARGS natively).
func scanQuery(rawQuery string, ia *protections.InspectionArgs, budget *budget) {
	if rawQuery == "" || budget.exceeded() {
		return
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// ParseQuery is permissive — it still returns whatever it could
		// parse on error. Fall through and walk what we got.
	}
	for key, vs := range values {
		name := key + ".b64decoded"
		for _, v := range vs {
			decoded, ok := TryDecode(v)
			if !ok {
				continue
			}
			if !budget.consume() {
				return
			}
			ia.GET = append(ia.GET, protections.ArgPair{
				Name:  name,
				Value: decoded,
			})
		}
	}
}
