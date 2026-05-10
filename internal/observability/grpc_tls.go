package observability

import (
	"crypto/tls"

	"google.golang.org/grpc/credentials"
)

// grpcCreds returns transport credentials for gRPC OTLP. Default to
// system roots with TLS 1.2+; users tunneling to a private collector
// should set tracing.insecure=true (or hand-roll headers + endpoint).
func grpcCreds() credentials.TransportCredentials {
	return credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
}
