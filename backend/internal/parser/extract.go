package parser

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

var urlRegex = regexp.MustCompile(`https?://[^\s<>"']+`)

func ExtractURLs(textPlain string, htmlBody string) []string {
	seen := map[string]struct{}{}
	var result []string

	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		result = append(result, u)
	}

	for _, m := range urlRegex.FindAllString(textPlain, -1) {
		add(m)
	}

	if htmlBody != "" {
		doc, err := html.Parse(strings.NewReader(htmlBody))
		if err == nil {
			var walk func(*html.Node)
			walk = func(n *html.Node) {
				if n.Type == html.ElementNode && strings.EqualFold(n.Data, "a") {
					for _, a := range n.Attr {
						if strings.EqualFold(a.Key, "href") {
							add(a.Val)
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c)
				}
			}
			walk(doc)
		}
	}

	return result
}
