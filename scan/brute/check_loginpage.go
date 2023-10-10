package brute

import (
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"net/url"
	"regexp"
	"strings"
)

func CheckLoginPage(inputurl string, body string) bool {
	if body == "" {
		req, err := httpx.Request(inputurl, "GET", "", true, nil)
		if err != nil {
			return false
		}
		body = req.Body
	}
	if funk.Contains(body, "<title> Login </title>") {
		return true
	}
	cssurl := regexp.MustCompile(`<link[^>]*href=['"](.*?)['"]`).FindAllStringSubmatch(body, -1)
	for _, v := range cssurl {
		if strings.Contains(v[1], ".css") {
			u, err := url.Parse(inputurl)
			if err != nil {
				return false
			}
			href, err := url.Parse(v[1])
			if err != nil {
				return false
			}
			if err != nil {
				return false
			}
			hrefurl := u.ResolveReference(href)
			if reqcss, err := httpx.Request(hrefurl.String(), "GET", "", true, nil); err == nil {
				if strings.Contains(reqcss.Body, "login") || strings.Contains(reqcss.Body, "Login") {
					return true
				}
			}
		}

		return false
	}
	return false
}
