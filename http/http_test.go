package http

import (
    // "fmt"
    "net/http"
    "testing"
    "reflect"
    // "time"
)

//TODO: Increase number of tests

var parseHPKPTests = []struct {
    s string
    p *HPKPProfile
}{
    {s: "max-age=5184000; pin-sha256=\"WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=\"; includeSubDomains",
     p: &HPKPProfile{5184000, 
                    []string{`WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=`}, 
                    true}},
    {s: `pin-sha256="d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="; pin-sha256="LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="; max-age=259200`,
     p: &HPKPProfile{259200, 
                    []string{`d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=`, `LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=`}, 
                    false}},
}

func TestParseHPKP(t *testing.T) {
    for _, tt := range parseHPKPTests {

        //t.Errorf(tt.s)

        r := new(http.Response)
        r.Header = make(http.Header)
        r.Header.Set("Public-Key-Pins", tt.s)

		if p := ParseHPKP(r); !reflect.DeepEqual(tt.p, p) {
			t.Errorf("HPKPProfile for %q = %q\n want %q\n", tt.s, p, tt.p)
		}
	}
}

var parseHSTSTests = []struct {
    s string
    p *HSTSProfile
}{
    {s: "max-age=31536000; includeSubdomains; preload",
     p: &HSTSProfile{31536000, 
                    true, 
                    true}},
    {s: `max-age=631138519`,
     p: &HSTSProfile{631138519, 
                     false,
                    false}},
}

func TestParseHSTS(t *testing.T) {
    for _, tt := range parseHSTSTests {

        //t.Errorf(tt.s)

        r := new(http.Response)
        r.Header = make(http.Header)
        r.Header.Set("Strict-Transport-Security", tt.s)

		if p := ParseHSTS(r); !reflect.DeepEqual(tt.p, p) {
			t.Errorf("HSTSProfile for %q = %q, want %q", tt.s, p, tt.p)
		}
	}
}


var parseXSSTests = []struct {
    s string
    p *XSSProfile
}{
    {s: `1; report=https://hsbc.co.uk/`,
     p: &XSSProfile{true,
                    true,
                    false,
                    "https://hsbc.co.uk/"}},
    {s: `1; mode=block`,
     p: &XSSProfile{true, 
                    true, 
                    true,
                    ""}},
    {s: `1`,
     p: &XSSProfile{true, 
                     true,
                    false,
                    ""}},
    {s: `0`,
     p: &XSSProfile{true,
                    false,
                    false,
                    ""}},
}

func TestParseXSS(t *testing.T) {
    for _, tt := range parseXSSTests {

        //t.Errorf(tt.s)

        r := new(http.Response)
        r.Header = make(http.Header)
        r.Header.Set("X-XSS-Protection", tt.s)

		if p := ParseXSS(r); !reflect.DeepEqual(tt.p, p) {
			t.Errorf("XSSProfile for %q = %q, want %q", tt.s, p, tt.p)
		}
	}
}

var parseXFOTests = []struct {
    s string
    p *XFOProfile
}{
    {s: `ALLOW-FROM https://*.google.com/`,
     p: &XFOProfile{true,
                    false,
                    "https://*.google.com/"}},
    {s: `SAMEORIGIN`,
     p: &XFOProfile{true, 
                    true,
                    ""}},
    {s: `deny`,
     p: &XFOProfile{true,
                    false,
                    ""}},
}

func TestParseXFO(t *testing.T) {
    for _, tt := range parseXFOTests {

        //t.Errorf(tt.s)

        r := new(http.Response)
        r.Header = make(http.Header)
        r.Header.Set("X-Frame-Options", tt.s)

		//t.Errorf("%+v", p)
		if p := ParseXFO(r); !reflect.DeepEqual(tt.p, p) {
			t.Errorf("XFOProfile for %q = %q, want %q", tt.s, p, tt.p)
		}
	}
}

var parseXCTOTests = []struct {
    s string
    p *XCTOProfile
}{
    {s: `nosniff`,
     p: &XCTOProfile{true, 
                    true}},
    {s: ``,
     p: &XCTOProfile{false,
                    false}},
    {s: `tonyfieldftw`,
     p: &XCTOProfile{true,
                    false}},
}

func TestParseXCTO(t *testing.T) {
    for _, tt := range parseXCTOTests {

        //t.Errorf(tt.s)

        r := new(http.Response)
        r.Header = make(http.Header)
        r.Header.Set("X-Content-Type-Options", tt.s)

		//t.Errorf("%+v", p)
		if p := ParseXCTO(r); !reflect.DeepEqual(tt.p, p) {
			t.Errorf("XCTOProfile for %q = %q, want %q", tt.s, p, tt.p)
		}
	}
}

