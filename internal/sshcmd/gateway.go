package sshcmd

// pickRoute decides how ConnectArgs reaches a host with a Gateway: it
// checks the direct way as the health check does (a TCP connect and the SSH
// banner, at most HealthTimeout each) and goes through the gateway only
// when the host is down directly, a host without a Gateway is not checked
// and its command line stays the same, every call checks again, a Host
// kept in memory moves between networks with its user
func pickRoute(h *Host) {
	h.RouteViaGateway(false)
	if h.Gateway == "" || h.Jump != "" {
		return
	}
	h.RouteViaGateway(CheckHealth(h).State == HealthDown)
}
