// Package netpolicy contains destination and log-sanitization policy shared by
// outbound protocol clients.
package netpolicy

import (
	"net"
	"net/url"
)

// RestrictedIP reports whether ip is unsuitable for public upstream traffic.
func RestrictedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 0 || (ip4[0] == 100 && (ip4[1]&0xc0) == 64)
	}
	return false
}

// SanitizeURL removes credentials, query parameters, and fragments before logging.
func SanitizeURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return invalidURLPlaceholder
	}
	parsed.User = nil
	parsed.RawQuery = emptyString
	parsed.Fragment = emptyString
	return parsed.String()
}
