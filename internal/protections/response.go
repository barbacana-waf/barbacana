package protections

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the JSON body returned when a request is blocked.
// No internal details are leaked — no rule IDs, no protection names,
// no stack traces.
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// WriteBlockResponse writes a 403 response with the standard JSON error body.
func WriteBlockResponse(w http.ResponseWriter, requestID string, statusCode int) {
	if statusCode == 0 {
		statusCode = http.StatusForbidden
	}
	resp := ErrorResponse{
		Error:     "blocked",
		RequestID: requestID,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}

// WriteErrorResponse writes a JSON error response with a custom status code
// and message. Used for non-403 blocks (e.g., 413, 415, 405).
func WriteErrorResponse(w http.ResponseWriter, requestID string, statusCode int, message string) {
	resp := ErrorResponse{
		Error:     message,
		RequestID: requestID,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp)
}
