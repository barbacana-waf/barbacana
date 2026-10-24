package base64decode

import (
	"bytes"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/protections"
)

// maxURLDecodedValues caps the URL-decoded copies of JSON strings added to a
// request. They are not base64 decodes, so they do not count against the
// flood budget; the cap just keeps a body of thousands of strings from
// producing thousands of synthetic args.
const maxURLDecodedValues = 50

// scanJSONBody is scanBody for a JSON document: it looks inside the strings
// the document holds rather than at its bytes. It returns false, having done
// nothing, when body is not valid JSON, and the caller falls back to the flat
// scan.
//
// The difference matters because JSON can write any character as an escape. A
// body whose every character is written \u00XX has no run of base64 in its
// bytes at all, yet the string it holds is a plain base64 blob, and the flat
// scan cannot see it. Walking the decoded strings does. The same walk gives
// URL-encoded values a second chance: unlike a form body, a JSON string is not
// URL-decoded by the parser, and CRS rules that do not apply a URL-decoding
// transformation would otherwise never see inside it.
func scanJSONBody(body []byte, ia *protections.InspectionArgs, b *budget) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	var strs []string
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return false
		}
		if s, ok := tok.(string); ok {
			strs = append(strs, s)
		}
	}

	idx, urlIdx := 0, 0
	for _, s := range strs {
		if b.exceeded() {
			break
		}
		scanRuns([]byte(s), ia, b, &idx)
		if urlIdx < maxURLDecodedValues && strings.Contains(s, "%") {
			if decoded, err := url.QueryUnescape(s); err == nil && decoded != s {
				ia.POST = append(ia.POST, protections.ArgPair{
					Name:  "body.urldecoded." + strconv.Itoa(urlIdx),
					Value: decoded,
				})
				urlIdx++
			}
		}
	}
	return true
}
