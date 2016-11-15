package email

import (
	"fmt"
	reflections "github.com/oleiade/reflections"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

//See https://tools.ietf.org/html/rfc6376 section 3.5 for more details
type DKIMSigProfile struct {
	//Required
	V  int64
	A  string
	B  string
	BH string
	D  string
	H  []string
	S  string
	//--------
	//Recommended
	T int64
	X int64 //Note: T < X is required
	//--------
	//Optional
	C string
	I string
	L int64
	Q string
	Z map[string]string
}

func handleError(err error) {
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
}

// Parses parameters of the format "xxx(=xxxx)?"
//TODO: move this function out to a library, it's repeated, but slightly edited from http/http.go
func parseParams(v string) (params map[string]string) {
	params = make(map[string]string)
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

func parseInt(str string) (r int64) {
	r, err := strconv.ParseInt(str, 10, 64)
	handleError(err)

	return
}

func contains(arr []string, str string) bool {
	for _, v := range arr {
		if v == str {
			return true
		}
	}
	return false
}

/*
   Notes:
   V : It MUST have the value "1" for implementations compliant with this version of DKIMSig.
   A : Signers SHOULD sign using "rsa-sha256" (according to standard, but see: https://www.wired.com/2012/10/dkim-vulnerability-widespread)
   BH: The hash of the canonicalized body part of the message as limited by the "l=" tag
   H : The field MUST NOT include the DKIM-Signature header field that is being created or
       verified but may include others.
   T : Implementations MAY ignore signatures that have a timestamp in the future.
   L : value MUST NOT be larger than the actual number of octets in the canonicalized message body.
   I : The domain part of the (email) address MUST be the same as, or a subdomain of, the value of the "d=" tag.
*/
func ScoreDKIMSig(p *DKIMSigProfile) (score int) {
	score = 0

	//TODO: L, I considerations as above
	if p.V != 1 || contains(p.H, "DKIM-Signature") || time.Now().Before(time.Unix(p.T, 0)) ||
		time.Unix(p.X, 0).Before(time.Unix(p.T, 0)) {
		return 0
	}

	if p.A == "rsa-sha256" {
		score += 2
	} else {
		score += 1
	}

	score += len(p.H)

	//TODO: more thorough DKIM scoring

	return score
}

//TODO: using reflections is probably very inefficient
//TODO: handle whitespace/char encodings
func ParseDKIMSig(record string) *DKIMSigProfile {
	p := DKIMSigProfile{}

	stripped := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, record)

	for key, value := range parseParams(stripped) {

		switch key {
		case "v", "l", "t", "x":
			err := reflections.SetField(&p, strings.ToUpper(key), parseInt(value))
			handleError(err)
		case "h":
			split := strings.Split(value, ":")
			err := reflections.SetField(&p, strings.ToUpper(key), split)
			handleError(err)
		case "z":
			m := make(map[string]string)
			for _, v := range strings.Split(value, "|") {
				s := strings.SplitN(v, ":", 2)
				m[s[0]] = s[1]
			}
			p.Z = m
		default:
			err := reflections.SetField(&p, strings.ToUpper(key), value)
			handleError(err)
		}
	}

	return &p
}
