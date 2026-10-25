package settings

import (
	"fmt"
	"strings"
)

// CertListed is the mode of Cert that signs certificates for the hosts in
// CertHosts
const CertListed = "listed"

// CertValidityDefault is the life of a certificate when CertValidity is 0,
// in minutes, CertValidityMax the longest one sshr signs
const (
	CertValidityDefault = 10
	CertValidityMax     = 8 * 60
)

// CertFor returns the principals a certificate for the host with id is
// signed for, target is where the host points now, ok is false for a host
// that logs in without one, a host that points elsewhere since it was
// listed or a mode this build does not know is an error, it never falls
// back to another way in
func (s Settings) CertFor(id, target string) (principals []string, ok bool, err error) {
	bound, listed := s.CertHosts[id]
	switch {
	case s.Cert == "" || !listed:
		return nil, false, nil
	case s.Cert != CertListed:
		return nil, false, fmt.Errorf("certificates are set to %q, a mode of a newer sshr, update sshr", s.Cert)
	case bound != target:
		return nil, false, fmt.Errorf("the host points elsewhere since its certificate was turned on, check it and turn it on again with sshr cert on")
	}
	for _, p := range strings.Split(s.CertPrincipals[id], ",") {
		if p = strings.TrimSpace(p); p != "" {
			principals = append(principals, p)
		}
	}
	if len(principals) == 0 {
		return nil, false, fmt.Errorf("the certificate of the host names no principal, turn it on again with sshr cert on --principal")
	}
	return principals, true, nil
}

// CertMinutes is the life of a certificate sshr signs, in minutes
func (s Settings) CertMinutes() int {
	switch {
	case s.CertValidity <= 0:
		return CertValidityDefault
	case s.CertValidity > CertValidityMax:
		return CertValidityMax
	}
	return s.CertValidity
}

// EnableCert lists the host with id for certificates for principals,
// bound to target, where it points now
func (s *Settings) EnableCert(id, target string, principals []string) {
	s.CertHosts = withKey(s.CertHosts, id, target)
	s.CertPrincipals = withKey(s.CertPrincipals, id, strings.Join(principals, ","))
	s.Cert = CertListed
}

// DisableCert takes the host with id off the list
func (s *Settings) DisableCert(id string) {
	s.CertHosts = withoutKey(s.CertHosts, id)
	s.CertPrincipals = withoutKey(s.CertPrincipals, id)
}

func withKey(m map[string]string, k, v string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for key, val := range m {
		out[key] = val
	}
	out[k] = v
	return out
}

func withoutKey(m map[string]string, k string) map[string]string {
	out := make(map[string]string, len(m))
	for key, val := range m {
		if key != k {
			out[key] = val
		}
	}
	return out
}
