package app

// pickRoute decides how ConnectArgs reaches a host with a Gateway: it
// checks the direct way as the health check does (a TCP connect and the SSH
// banner, at most HealthTimeout each) and goes through the gateway only
// when the host is down directly, a host without a Gateway is not checked
// and its command line stays the same
func pickRoute(h *Host) {
	if h.Gateway == "" || h.Jump != "" || h.routeChecked {
		return
	}
	h.routeChecked = true
	if CheckHealth(h).State == HealthDown {
		h.route = h.Gateway
	}
}

// Via is the jump spec the connection goes through: Jump, or the Gateway
// once ConnectArgs found the host down directly, empty for a direct one
func (h *Host) Via() string {
	if h.Jump != "" {
		return h.Jump
	}
	return h.route
}
