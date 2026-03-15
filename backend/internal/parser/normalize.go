package parser

import (
	"net/url"
	"strings"
)

func NormalizeURL(raw string) (string, string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", false
	}

	if strings.HasPrefix(raw, "www.") {
		raw = "http://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", "", false
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Fragment = ""
	u.Host = host

	return u.String(), host, true
}
