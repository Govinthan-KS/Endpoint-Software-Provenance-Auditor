package classifier

import (
	"testing"
)

func TestCheckConnectivity(t *testing.T) {
	// Probe does not panic or hang
	res := CheckConnectivity()
	t.Logf("Network preflight connectivity status: %v", res)
}
