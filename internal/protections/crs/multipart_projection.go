package crs

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"sort"
	"strings"
)

// Multipart bodies and the inspection window.
//
// inspection.max_inspect_size bounds what the rules read, and the design
// defines that as non-file bytes: no loaded rule reads the contents of an
// uploaded file (the only file-related variable any of them uses is the
// combined file size, which is not configured), so passing them to Coraza
// spends memory and CPU on bytes nothing looks at, and a 128KB limit used to
// reject every upload bigger than that.
//
// projectMultipart builds the copy of a multipart/form-data body that Coraza
// is given instead when the real one does not fit the window: every part keeps
// its headers and the contents of its non-file fields, and a part Coraza files
// as an upload keeps its headers but loses its contents. Everything the rules
// do read is preserved: field values (ARGS), field and file names, part
// headers (and so the php2shell part-header and empty-file-control counts),
// and the structure Coraza's multipart parser walks. The upstream still
// receives the original body; the projection only exists inside Evaluate.
//
// The split into parts and the file/field decision use the same library calls
// Coraza makes (mime/multipart and Part.FileName), so both sides agree on
// where parts end and which are uploads. When they could disagree, the
// projection errs towards keeping content: a part is only emptied if
// Part.FileName is non-empty, which covers filename and filename*.
// projection_test.go runs the same bodies through Coraza before and after
// projecting to hold this to account.

// isMultipartFormData reports whether Coraza would run its multipart parser on
// a body with this Content-Type, and returns the boundary parameter.
func isMultipartFormData(contentType string) (boundary string, ok bool) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return "", false
	}
	return params["boundary"], true
}

// projectMultipart returns the projection of body, which must be a
// multipart/form-data body with the given boundary. It stops as soon as the
// projection is longer than maxOut bytes and reports that with truncated=true;
// the returned bytes are then a prefix of the projection, longer than maxOut.
//
// err is whatever the multipart reader reported if it could not walk the body:
// multipart.ErrMessageTooLarge for a part whose header block is too large, or a
// malformed-body error. The projection is then not usable.
func projectMultipart(body []byte, boundary string, maxOut int) (out []byte, truncated bool, err error) {
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var buf bytes.Buffer
	for {
		part, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}

		buf.WriteString("--")
		buf.WriteString(boundary)
		buf.WriteString("\r\n")
		keys := make([]string, 0, len(part.Header))
		for k := range part.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range part.Header[k] {
				buf.WriteString(k)
				buf.WriteString(": ")
				buf.WriteString(v)
				buf.WriteString("\r\n")
			}
		}
		buf.WriteString("\r\n")

		if part.FileName() != "" {
			// An upload: its contents are the bytes that do not count.
			if _, err := io.Copy(io.Discard, part); err != nil {
				return nil, false, err
			}
		} else {
			// Copy no more than the window has room for, so a huge text field
			// cannot be duplicated in full just to be turned away.
			room := int64(maxOut-buf.Len()) + 1
			n, err := io.CopyN(&buf, part, room)
			if err != nil && err != io.EOF {
				return nil, false, err
			}
			if n == room {
				return buf.Bytes(), true, nil
			}
		}
		buf.WriteString("\r\n")

		if buf.Len() > maxOut {
			return buf.Bytes(), true, nil
		}
	}
	buf.WriteString("--")
	buf.WriteString(boundary)
	buf.WriteString("--\r\n")
	return buf.Bytes(), buf.Len() > maxOut, nil
}

// errMessageTooLarge reports whether err is the multipart reader refusing a
// part whose header block is too large to parse: the condition rule 212002
// detects, and the shape of the PHP2Shell header-flood vector.
func errMessageTooLarge(err error) bool {
	return errors.Is(err, multipart.ErrMessageTooLarge) ||
		(err != nil && strings.Contains(err.Error(), "message too large"))
}
