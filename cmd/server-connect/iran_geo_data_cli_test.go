package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestIRGeoEstimateDataCLIIsOfflineReadOnlyAndNotActivation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing-private-store")
	manager := sc.New(dir, filepath.Join(dir, "missing-core"), 20807)
	for _, jsonMode := range []bool{true, false} {
		code, out, errs := hostDriftCapturedOutput(t, func() int {
			return run(jsonMode, manager, []string{"smart-routing-data"})
		})
		if code != 0 || errs != "" {
			t.Fatalf("offline report failed: %d %q %q", code, out, errs)
		}
		if jsonMode {
			var response struct {
				OK   bool                     `json:"ok"`
				Data sc.IranGeoSnapshotStatus `json:"data"`
			}
			if err := json.Unmarshal([]byte(out), &response); err != nil || !response.OK ||
				response.Data.Country != "IR" || response.Data.IPv4Count != 2024 ||
				response.Data.IPv6Count != 1014 || response.Data.ActivationReady ||
				response.Data.SafeForGeographicRouting || response.Data.PublisherSignatureVerified || response.Data.License != "CC-BY-4.0" {
				t.Fatalf("unsafe or incomplete registry report: %+v %v", response, err)
			}
		} else if !strings.Contains(out, "dbip_lite_country_geolocation_estimate") ||
			!strings.Contains(out, `"safe_for_geographic_routing": false`) ||
			!strings.Contains(out, `"activation_ready": false`) {
			t.Fatalf("text CLI omitted the routing warning: %s", out)
		}
	}
	code, out, _ := hostDriftCapturedOutput(t, func() int {
		return run(true, manager, []string{"smart-routing-data", "--file", "/tmp/unsafe"})
	})
	if code == 0 || !strings.Contains(out, "invalid_arguments") {
		t.Fatalf("unapproved import flag accepted: %d %s", code, out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("registry inspection altered private product state")
	}
}
