// Package openapi implements OpenAPI contract enforcement protections.
package openapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/barbacana-waf/barbacana/internal/config"
	"github.com/barbacana-waf/barbacana/internal/protections"
)

const (
	OpenAPIPath        = "openapi-path"
	OpenAPIMethod      = "openapi-method"
	OpenAPIParams      = "openapi-params"
	OpenAPIBody        = "openapi-body"
	OpenAPIContentType = "openapi-content-type"
)

// Validator validates requests against an OpenAPI spec.
type Validator struct {
	router     routers.Router
	disabled   map[string]bool
	strict     bool
	detectOnly bool
	routeID    string
	shadowLog  bool
}

// NewValidator loads an OpenAPI spec and creates a validator.
func NewValidator(specPath string, routeCfg config.Resolved) (*Validator, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("load openapi spec %s: %w", specPath, err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		return nil, fmt.Errorf("validate openapi spec %s: %w", specPath, err)
	}

	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("create openapi router: %w", err)
	}

	strict := true
	// Start with the route-level disable map so that entries like "openapi-body"
	// in the route's disable list are respected here.
	disabled := map[string]bool{}
	for k, v := range routeCfg.Disable {
		disabled[k] = v
	}
	if routeCfg.OpenAPI != nil {
		if routeCfg.OpenAPI.Strict != nil {
			strict = *routeCfg.OpenAPI.Strict
		}
		for _, d := range routeCfg.OpenAPI.Disable {
			disabled[d] = true
		}
	}

	return &Validator{
		router:     router,
		disabled:   disabled,
		strict:     strict,
		detectOnly: routeCfg.Mode == config.ModeDetect || !strict,
		routeID:    routeCfg.ID,
		shadowLog:  routeCfg.ShadowAPILogging,
	}, nil
}

// Validate checks the request against the OpenAPI spec.
func (v *Validator) Validate(ctx context.Context, r *http.Request) protections.Decision {
	route, pathParams, err := v.router.FindRoute(r)
	if err != nil {
		// Path not found in spec.
		if !protections.IsDisabled(OpenAPIPath, v.disabled) {
			if v.shadowLog {
				slog.InfoContext(ctx, "shadow API: undeclared path",
					"route", v.routeID,
					"path", r.URL.Path,
					"method", r.Method,
				)
			}
			if v.detectOnly {
				return protections.Allow()
			}
			return protections.Decision{
				Block:      true,
				Protection: OpenAPIPath,
				Reason:     fmt.Sprintf("path %s not declared in spec", r.URL.Path),
			}
		}
		return protections.Allow()
	}

	// Method check.
	if !protections.IsDisabled(OpenAPIMethod, v.disabled) {
		if route.Operation == nil {
			if v.detectOnly {
				return protections.Allow()
			}
			return protections.Decision{
				Block:      true,
				Protection: OpenAPIMethod,
				Reason:     fmt.Sprintf("method %s not declared for path %s", r.Method, r.URL.Path),
			}
		}
	}

	// Build validation input.
	input := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			MultiError: true,
		},
	}

	validationErr := openapi3filter.ValidateRequest(ctx, input)
	if validationErr == nil {
		return protections.Allow()
	}

	// Classify the error.
	errMsg := validationErr.Error()
	protection := classifyError(errMsg, v.disabled)
	if protection == "" {
		return protections.Allow()
	}

	if v.detectOnly {
		return protections.Allow()
	}
	return protections.Decision{
		Block:      true,
		Protection: protection,
		Reason:     errMsg,
	}
}

func classifyError(msg string, disabled map[string]bool) string {
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "content type"):
		if !protections.IsDisabled(OpenAPIContentType, disabled) {
			return OpenAPIContentType
		}
	case strings.Contains(lower, "request body"):
		if !protections.IsDisabled(OpenAPIBody, disabled) {
			return OpenAPIBody
		}
	case strings.Contains(lower, "parameter"):
		if !protections.IsDisabled(OpenAPIParams, disabled) {
			return OpenAPIParams
		}
	default:
		if !protections.IsDisabled(OpenAPIBody, disabled) {
			return OpenAPIBody
		}
	}
	return ""
}

// Register adds OpenAPI protections to the registry.
func Register(reg *protections.Registry) {
	reg.Add(namedProtection{name: OpenAPIPath})
	reg.Add(namedProtection{name: OpenAPIMethod})
	reg.Add(namedProtection{name: OpenAPIParams})
	reg.Add(namedProtection{name: OpenAPIBody})
	reg.Add(namedProtection{name: OpenAPIContentType})
}

type namedProtection struct{ name string }

func (n namedProtection) Name() string     { return n.name }
func (n namedProtection) Category() string { return "" }
func (n namedProtection) CWE() string      { return protections.CWEForProtection(n.name) }
func (n namedProtection) Evaluate(_ context.Context, _ *http.Request) protections.Decision {
	return protections.Allow()
}
