package classifier

import (
	"net"
	"time"
)

// CheckConnectivity performs a fast-fail connectivity probe using standard library net.DialTimeout.
// Tests 1.1.1.1:53 with a strict 350ms timeout, falling back to 8.8.8.8:53.
func CheckConnectivity() bool {
	timeout := 350 * time.Millisecond
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", timeout)
	if err == nil {
		conn.Close()
		return true
	}

	conn, err = net.DialTimeout("tcp", "8.8.8.8:53", timeout)
	if err == nil {
		conn.Close()
		return true
	}

	return false
}
