package http

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type HPKPProfile struct {
	//TODO: possibly include pincount
	Maxage            int64
	Pins              []string
	IncludeSubdomains bool
}

type HSTSProfile struct {
	Maxage            int64
	IncludeSubdomains bool
	Preload           bool
	// TODO: check whether preload flag matches with info found on https://www.chromium.org/hsts
}

type XSSProfile struct {
	Present bool
	Enabled bool
	Blocked bool
	Report  string
}

type XFOProfile struct { // X-Frame-Options
	Present    bool
	SameOrigin bool
	AllowFrom  string
}

// Both present to handle case of XCTO header is malformed
type XCTOProfile struct { // X-Content-Type-Options
	Present bool
	Nosniff bool
}

//TODO: in general we may need to handle upper/lower case headers?
// func main() {
// 	github := "https://github.com/"
// 	resp := headRequest(github)

// 	hpkp := parseHPKP(resp)
// 	fmt.Printf("\n")
// 	fmt.Printf("%+v\n", hpkp)

// }

var sm = map[bool]int{
	false: 0,
	true:  1,
}

//TODO: validate HPKP pins
func ScoreHPKP(p *HPKPProfile) (s int) {
	return sm[p.Maxage > 0] + len(p.Pins) + sm[p.IncludeSubdomains]
}

//TODO: decide on what scoring mechanism to use based on the cache time
func ScoreHSTS(p *HSTSProfile) (s int) {
	return sm[p.Maxage > 0] + sm[p.IncludeSubdomains] + sm[p.Preload]
}

func ScoreXSS(p *XSSProfile) (s int) {
	return sm[p.Present] + sm[p.Enabled] + sm[p.Blocked] + sm[p.Report != ""]
}

func ScoreXFO(p *XFOProfile) (s int) {
	return sm[p.Present] + sm[p.SameOrigin] + sm[p.AllowFrom != ""]
}

func ScoreXCTO(p *XCTOProfile) (s int) {
	return sm[p.Present] + sm[p.Nosniff]
}

// Parses parameters of the format "xxx(=xxxx)?"
func parseParams(header http.Header, key string) (params map[string]string) {
	params = make(map[string]string)
	v := header.Get(key)
	p := strings.Split(v, ";")
	re := regexp.MustCompile("([A-Za-z0-9-]*)[=\"]*([^\"]*)?")

	for _, s := range p {
		s = strings.TrimSpace(s)
		match := re.FindStringSubmatch(s)
		pk := strings.ToLower(match[1])

		pv := match[2]
		if params[pk] == "" {
			params[pk] = pv
		} else {
			params[pk] = params[pk] + "," + pv
		}
	}

	return
}

/*
   Note, the existence of HPKP doesn't imply that it's a secure one
   http://news.netcraft.com/archives/2016/03/22/secure-websites-shun-http-public-key-pinning.html
   is a good start
   Furthermore, we ought to assess the effectiveness with the cache (max-age) time.
   Longer cache means better security, but if the implementation is incorrect then vendors can potentially lock genuine visitors out for the cache length
*/
func ParseHPKP(resp *http.Response) (p *HPKPProfile) {
	params := parseParams(resp.Header, "Public-Key-Pins")

	maxage, err := strconv.ParseInt(params["max-age"], 10, 64)

	if err != nil {
		maxage = 0
	}

	_, includesubdomains := params["includesubdomains"]

	profile := HPKPProfile{maxage,
		strings.Split(params["pin-sha256"], ","),
		includesubdomains}
	return &profile
}

func ParseHSTS(resp *http.Response) (p *HSTSProfile) {
	params := parseParams(resp.Header, "Strict-Transport-Security")

	maxage, err := strconv.ParseInt(params["max-age"], 10, 64)

	if err != nil {
		maxage = 0
	}

	_, sub := params["includesubdomains"]
	_, preload := params["preload"]

	profile := HSTSProfile{maxage, sub, preload}
	return &profile
}

/*
   flag can either be:
   - Not present
   - 0 (explicitly disabled)
   - 1 without "mode=block"
   - 1 with "mode=block" which prevents IE/WebKit browsers from sanitizing potential attacks
   - 1 with "report=URL" tells the user-agent to report potential attacks to URL
   TODO: create scoring mechanism between these 4 states
*/
func ParseXSS(resp *http.Response) (p *XSSProfile) {
	params := parseParams(resp.Header, "X-XSS-Protection")
	_, enabled := params["1"]

	return &XSSProfile{hasHeader(resp, "X-XSS-Protection"),
		enabled,
		params["mode"] == "block",
		params["report"]}
}

/*
   X-Frame-Options generally used to prevent content from this URL being clickjacked elsewhere
   Flag can either be:
   - Not present
   - DENY
   - SAMEORIGIN (from same domain)
   - ALLOW-FROM (from specified domains)

   TODO: find out difference between this and Frame-Options, I think Frame-Options is just obsolete?
   TODO: is there any use in discrimination between sameorigin and allow-from? Maybe need to consider the case of subdomains
*/
func ParseXFO(resp *http.Response) (p *XFOProfile) {
	var allowfrom string
	head := strings.ToLower(resp.Header.Get("X-Frame-Options"))

	comps := strings.SplitN(head, " ", 2)
	if comps[0] == "allow-from" {
		allowfrom = comps[1]
	}

	return &XFOProfile{hasHeader(resp, "X-Frame-Options"),
		strings.HasPrefix(head, "sameorigin"),
		allowfrom}
}

/*
   Prevents MIME based attacks. Possible values:
   - nosniff
*/
func ParseXCTO(resp *http.Response) (p *XCTOProfile) {

	head := strings.ToLower(resp.Header.Get("X-Content-Type-Options"))

	return &XCTOProfile{hasHeader(resp, "X-Content-Type-Options"),
		strings.HasPrefix(head, "nosniff")}

}

func hasHeader(resp *http.Response, str string) (b bool) {
	return (resp.Header.Get(str) != "")
}
