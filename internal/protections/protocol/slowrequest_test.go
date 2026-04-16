package protocol

import (
	"encoding/json"
	"testing"

	"github.com/barbacana-waf/barbacana/internal/config"
)

func TestSlowRequestInCaddyConfig(t *testing.T) {
	c := &config.Config{
		Version: "v1alpha1",
		Routes:  []config.Route{{Upstream: "http://app:8000", UpstreamTimeout: "30s"}},
	}
	c.Global.Protocol.SlowRequestHeaderTimeout = "10s"
	v := 100
	c.Global.Protocol.HTTP2MaxConcurrentStreams = &v
	v2 := 65536
	c.Global.Protocol.HTTP2MaxDecodedHeaderBytes = &v2

	raw, err := config.Compile(c, nil)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	apps, _ := got["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	proxy, _ := servers["proxy"].(map[string]any)

	if proxy["read_header_timeout"] != "10s" {
		t.Errorf("read_header_timeout = %v", proxy["read_header_timeout"])
	}
}
