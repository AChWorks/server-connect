package sc

import (
	"strings"
	"testing"
)

func fixtureSelectiveRequest() SelectivePlanRequest {
	return SelectivePlanRequest{
		EndpointIP: "198.51.100.1", ManagementPeerIP: "198.51.100.2",
		TunnelInterface: "scplan0", Destinations: []string{"2606:4700:4700::/48", "8.8.8.0/24"},
	}
}

// A deterministic legacy journal fixture, NOT a live planner or network
// observation. Only persisted record validation/abandonment consumes this.
func planFromFixture(t *testing.T, req SelectivePlanRequest) (SelectiveRoutePlan, error) {
	t.Helper()
	validated, err := validateSelectiveRequest(req)
	if err != nil {
		return SelectiveRoutePlan{}, err
	}
	plan := SelectiveRoutePlan{
		Mode: "selective_preview", ReadOnly: true,
		Endpoint: validated.endpoint.String(), ManagementPeer: validated.peer.String(),
		TunnelInterface: validated.device, RouteTable: selectiveFirstTable,
		ObservationSHA256: strings.Repeat("a", 64),
	}
	for i, prefix := range validated.prefixes {
		family := "ipv4"
		if prefix.Addr().Is6() {
			family = "ipv6"
		}
		plan.Routes = append(plan.Routes, PlannedRoute{
			Family: family, Destination: prefix.String(), Table: plan.RouteTable, Device: plan.TunnelInterface,
		})
		plan.Rules = append(plan.Rules, PlannedRule{
			Family: family, Destination: prefix.String(), Table: plan.RouteTable, Priority: selectiveFirstPriority + i,
		})
	}
	plan.PlanSHA256, err = selectivePlanDigest(plan)
	return plan, err
}
