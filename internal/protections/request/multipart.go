package request

import (
	"context"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

const (
	MultipartFileLimit       = "multipart-file-limit"
	MultipartFileSize        = "multipart-file-size"
	MultipartAllowedTypes    = "multipart-allowed-types"
	MultipartDoubleExtension = "multipart-double-extension"
)

// MultipartValidator checks file upload protections.
type MultipartValidator struct {
	cfg config.Resolved
}

func NewMultipartValidator(cfg config.Resolved) *MultipartValidator {
	return &MultipartValidator{cfg: cfg}
}

// Validate checks multipart file uploads against configured limits.
// Should only be called if the route accepts multipart/form-data.
func (mv *MultipartValidator) Validate(ctx context.Context, r *http.Request) protections.Decision {
	if !mv.cfg.RunMultipartParser {
		return protections.Allow()
	}

	ct := r.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil || mediaType != "multipart/form-data" {
		return protections.Allow()
	}

	boundary := params["boundary"]
	if boundary == "" {
		return protections.Allow()
	}

	reader := multipart.NewReader(r.Body, boundary)
	disabled := mv.cfg.Disable
	fileCount := 0

	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}

		filename := part.FileName()
		if filename == "" {
			part.Close()
			continue // not a file upload
		}
		fileCount++

		// File count limit.
		if !protections.IsDisabled(MultipartFileLimit, disabled) {
			if fileCount > mv.cfg.Multipart.FileLimit {
				part.Close()
				return protections.Decision{
					Block: true, Protection: MultipartFileLimit,
					Reason: fmt.Sprintf("file count %d exceeds limit %d",
						fileCount, mv.cfg.Multipart.FileLimit),
				}
			}
		}

		// Double extension check.
		if !protections.IsDisabled(MultipartDoubleExtension, disabled) && mv.cfg.Multipart.DoubleExtension {
			if hasDoubleExtension(filename) {
				part.Close()
				return protections.Decision{
					Block: true, Protection: MultipartDoubleExtension,
					Reason: fmt.Sprintf("double extension in filename %q", filename),
				}
			}
		}

		// MIME type check.
		if !protections.IsDisabled(MultipartAllowedTypes, disabled) && len(mv.cfg.Multipart.AllowedTypes) > 0 {
			partCT := part.Header.Get("Content-Type")
			if partCT == "" {
				// Guess from extension.
				partCT = mime.TypeByExtension(filepath.Ext(filename))
			}
			if partCT != "" && !isTypeAllowed(partCT, mv.cfg.Multipart.AllowedTypes) {
				part.Close()
				return protections.Decision{
					Block: true, Protection: MultipartAllowedTypes,
					Reason: fmt.Sprintf("file type %q not allowed", partCT),
				}
			}
		}

		// File size check — read the part to count bytes.
		if !protections.IsDisabled(MultipartFileSize, disabled) {
			size := int64(0)
			buf := make([]byte, 32*1024)
			for {
				n, readErr := part.Read(buf)
				size += int64(n)
				if size > mv.cfg.Multipart.FileSize {
					part.Close()
					return protections.Decision{
						Block: true, Protection: MultipartFileSize,
						Reason: fmt.Sprintf("file %q exceeds size limit %d",
							filename, mv.cfg.Multipart.FileSize),
					}
				}
				if readErr != nil {
					break
				}
			}
		}

		part.Close()
	}

	return protections.Allow()
}

func hasDoubleExtension(filename string) bool {
	// "shell.php.jpg" has two dots -> double extension.
	base := filepath.Base(filename)
	parts := strings.Split(base, ".")
	if len(parts) < 3 {
		return false
	}
	// Check if any non-final extension is a known risky extension.
	risky := map[string]bool{
		"php": true, "phtml": true, "phar": true,
		"exe": true, "bat": true, "cmd": true, "com": true,
		"sh": true, "bash": true, "cgi": true,
		"jsp": true, "jspx": true, "asp": true, "aspx": true,
		"py": true, "rb": true, "pl": true,
	}
	// Skip first element (filename), skip last (final extension).
	for _, ext := range parts[1 : len(parts)-1] {
		if risky[strings.ToLower(ext)] {
			return true
		}
	}
	return false
}

func isTypeAllowed(ct string, allowed []string) bool {
	base := ct
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		base = strings.TrimSpace(ct[:idx])
	}
	base = strings.ToLower(base)
	for _, a := range allowed {
		if strings.ToLower(a) == base {
			return true
		}
	}
	return false
}

// RegisterMultipart adds multipart protections to the registry.
func RegisterMultipart(reg *protections.Registry) {
	reg.Add(namedProtection{name: MultipartFileLimit})
	reg.Add(namedProtection{name: MultipartFileSize})
	reg.Add(namedProtection{name: MultipartAllowedTypes})
	reg.Add(namedProtection{name: MultipartDoubleExtension})
}
