package dns

import (
	b64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	//netaddr "github.com/ziutek/utils/netaddr"
	reflections "github.com/oleiade/reflections"
)

//TODO: handle None, PermError, TempError?
//For SPF
const (
	UNDEF     = iota //0
	PASS             //1
	FAIL             //2
	SOFT_FAIL        //3
	NEUTRAL          //4
)

//For DMARC, might be redundant
// const (
//     NONE = iota //0
//     QUARANTINE  //1
//     REJECT      //2
// )

type SPFProfile struct {
	IP4     IPRange
	IP6     IPRange
	A       IPRange
	MX      IPRange
	PTR     map[string]int
	EXISTS  map[string]int
	INCLUDE map[string]int

	all     int64
	version int64

	IP     string
	Domain string
	Record string
}

//See https://tools.ietf.org/html/rfc6376
type DKIMDNSProfile struct {
	V int64
	G string
	H string
	K string
	N string
	P string
	S string
	T map[string]bool
}

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

/*
   A good explanation for DMARC: https://blog.returnpath.com/demystifying-the-dmarc-record/

   v   Protocol version    v=DMARC1
   pct Percentage of messages subjected to filtering   pct=20
   ruf Reporting URI for forensic reports  ruf=mailto:authFail@example.com
   rua Reporting URI of aggregate reports  rua=mailto:aggrep@example.com
   p   Policy for organizational domain    p=quarantine
   sp  Policy for subdomains of the OD sp=reject
   adkim   Alignment mode for DKIM adkim=s
   aspf    Alignment mode for SPF  aspf=r
*/
type DMARCProfile struct {
	V     int64
	PCT   int64
	RUF   string
	RUA   string
	P     string //change to enum?
	SP    string //change to enum?
	ADKIM string
	ASPF  string

	RF string
	RI int64

	/*
	   There are four values to the fo: tag:
	   0: Generate a DMARC Failure report if all underlying authentication mechanisms Fail to produce an aligned “Pass” result. (Default)
	   1: Generate a DMARC Failure report if any underlying authentication mechanism produced something other than an aligned “Pass” result.
	   d: Generate a DKIM Failure report if the message had a signature that Failed evaluation, regardless of its alignment.
	   s: Generate an SPF Failure report if the message Failed SPF evaluation, regardless of its alignment.
	*/
	FO string

	Domain string
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

// dmarc policy
var dp = map[string]int{
	"none":       0,
	"quarantine": 1,
	"reject":     2,
}

// dmarc alignment
var da = map[string]int{
	"r": 0,
	"s": 1,
}

var dfo = map[string]int{
	"0": 0,
	"d": 1,
	"s": 1,
	"1": 2,
}

func ScoreDMARC(p *DMARCProfile) int {

	if p.V != 1 {
		return 0
	}

	if p.RUF != "" && !strings.HasSuffix(p.RUF, p.Domain) {
		return 0
	}

	if p.RUA != "" && !strings.HasSuffix(p.RUA, p.Domain) {
		return 0
	}

	return int(p.PCT/100) *
		(dp[p.P] +
			dp[p.SP] +
			da[p.ADKIM] +
			da[p.ASPF] +
			dfo[p.FO])
}

func ScoreDKIM(p_sig *DKIMSigProfile) int {

	if p_sig.S == "" || p_sig.D == "" {
		//can't do DKIM lookup without these required fields
		return 0
	}

	txts, err := net.LookupTXT(p_sig.S + "._domainkey." + p_sig.D)
	//TODO: better error handling
	handleError(err)

	p_dns := ParseDKIMDNS(txts[0])

	return scoreDKIMDNS(p_dns)
}

func scoreDKIMDNS(p_dns *DKIMDNSProfile) int {

	if p_dns.T["y"] {
		//DKIM isn't active, since t=y denotes testing mode
		return 0
	}

	sDec, _ := b64.StdEncoding.DecodeString(p_dns.P)

	//TODO: What's the significance of this length?
	return len(sDec)

}

// From: https://github.com/mindreframer/golang-stuff/blob/master/github.com/dotcloud/docker/network.go
// Given a netmask, calculates the number of available hosts
func networkSize(mask net.IPMask) int32 {
	m := net.IPv4Mask(0, 0, 0, 0)
	for i := 0; i < net.IPv4len; i++ {
		m[i] = ^mask[i]
	}

	return int32(binary.BigEndian.Uint32(m) + 1)
}

func scoreIPNets(nets []net.IPNet) (score float64) {

	if len(nets) == 0 {
		return 0
	}

	var netno int32 = 1
	for _, net := range nets {
		netno += networkSize(net.Mask)
	}
	//TODO: remove magic numbers

	if math.IsNaN(float64(netno)) {
		netno = math.MaxInt32
	}

	// fmt.Fprintf(os.Stderr, "%f", 10.450842 - (0.450842*math.Log(float64(netno))))
	// os.Exit(1)

	return 10.450842 - (0.450842 * math.Log(float64(netno)))
}

func ScoreSPF(p *SPFProfile) (score float64) {

	score = 0

	if p.all == PASS {
		return 0
	}

	fields, _ := reflections.Fields(p)
	for _, field := range fields {
		switch field {
		case "IP4", "A", "MX":
			f, err := reflections.GetField(p, field)
			handleError(err)
			arr, err := reflections.GetField(f, "Pass")
			handleError(err)
			score += scoreIPNets(arr.([]net.IPNet))
		case "PTR", "EXISTS", "INCLUDE":
			f, err := reflections.GetField(p, field)
			handleError(err)
			for addr, _ := range f.(map[string]int) {
				if strings.HasSuffix(addr, p.Domain) {
					score += 10
				} else if addr != "" {
					score -= 10
				}
			}
		}
	}

	//TODO: exists: handle macros
	//TODO: include: lookup SPF record for domain, check if the current domain/ip controls this addr

	return
}

//TODO: may need to strip some chars at the start of domain, this func currently expects a second-level domain e.g. example.com
func ParseDMARC(record string, domain string) *DMARCProfile {
	p := DMARCProfile{Domain: domain, PCT: 100, RF: "AFRF", RI: 86400, FO: "0"}

	for key, value := range parseParams(record) {

		switch key {
		case "v":
			value = strings.TrimLeft(value, "DMARC")
			fallthrough
		case "pct", "ri":
			err := reflections.SetField(&p, strings.ToUpper(key), parseInt(value))
			handleError(err)
		case "ruf", "rua", "p", "sp", "adkim", "aspf", "rf", "fo":
			//p.P = value
			err := reflections.SetField(&p, strings.ToUpper(key), value)
			handleError(err)
		default:
			//undefined field
		}
	}

	return &p
}

func ParseDKIMDNS(record string) *DKIMDNSProfile {
	p := DKIMDNSProfile{}

	for key, value := range parseParams(record) {
		switch key {
		case "v":
			v := strings.TrimLeft(value, "DKIM")
			err := reflections.SetField(&p, strings.ToUpper(key), parseInt(v))
			handleError(err)
		case "t":
			m := make(map[string]bool)
			for _, k := range strings.Split(value, ",") {
				m[k] = true
			}
			err := reflections.SetField(&p, strings.ToUpper(key), m)
			handleError(err)
		case "g", "h", "k", "n", "p", "s":
			err := reflections.SetField(&p, strings.ToUpper(key), value)
			handleError(err)
		}

	}
	return &p
}

func ParseSPF(record string, IP string) (p *SPFProfile) {
	split := strings.Split(record, " ")
	version := parseInt(strings.TrimPrefix(split[0], "v=spf"))

	p = &SPFProfile{version: version, Record: record, IP: IP}

	for _, mech := range split[1:] {
		ParseMechanism(mech, p)
	}

	return
}

var ParseMechPrefixes = map[string]int{
	"+": PASS,
	"-": FAIL,
	"~": SOFT_FAIL,
	"?": NEUTRAL,
}

//TODO: Check for confusion in the record
//TODO: Issue that the Parsed version will be static, whereas SPF records are more dynamic in nature
//TODO: Probably refactor this
func ParseMechanism(mech string, p *SPFProfile) {

	prefix := ParseMechPrefixes[string(mech[0])]
	if prefix == 0 {
		prefix = PASS
	}

	//if there's a prefix, trim it
	m := strings.TrimLeft(mech, "+-~?")

	if m == "all" {
		p.all = int64(prefix)
	}

	split := strings.SplitN(m, ":", 2)

	//Use of boolean switch makes for more boilerplate, but required for correctness
	switch {
	case strings.HasPrefix(split[0], "ip4"):
		ParseIPRange(split[1], prefix, &p.IP4)
	case strings.HasPrefix(split[0], "ip6"):
		ParseIPRange(split[1], prefix, &p.IP6)
	case strings.HasPrefix(split[0], "a"):
		if len(split) == 1 {
			ParseIPRange(strings.Replace(split[0], "a", p.IP, 1),
				prefix,
				&p.A)
		} else {
			ParseDomain(split[1], prefix, p.A)
		}
	case strings.HasPrefix(split[0], "mx"):
		if len(split) == 1 {
			ParseIPRange(strings.Replace(split[0], "mx", p.IP, 1),
				prefix,
				&p.MX)
		} else {
			ParseDomain(split[1], prefix, p.MX)
		}
	case strings.HasPrefix(split[0], "ptr"):
		var ptr []string
		var err error

		if len(split) == 1 {
			//ptr
			ptr, err = net.LookupAddr(p.Domain)

		} else {
			//ptr:<domain>
			ptr, err = net.LookupAddr(split[1])
		}

		handleError(err)
		for _, addr := range ptr {
			(*p).PTR[addr] = prefix
		}
	case strings.HasPrefix(split[0], "exists"):
		//exists:<domain>
		//TODO: handle macros
		(*p).EXISTS[split[1]] = prefix
	case strings.HasPrefix(split[0], "include"):
		//include:<domain>
		//TODO: lookup SPF record for domain
		(*p).INCLUDE[split[1]] = prefix
	}
}

func ParseDomain(domain string, prefix int, ipr IPRange) {
	split := strings.SplitN(domain, "/", 2)

	hosts, err := net.LookupHost(split[0])
	handleError(err)

	for _, host := range hosts {
		if len(split) == 1 {
			ParseIPRange(host, prefix, &ipr)
		} else {
			ParseIPRange(host+"/"+split[1], prefix, &ipr)
		}
	}
}

type IPRange struct {
	Pass      []net.IPNet
	Fail      []net.IPNet
	Soft_Fail []net.IPNet
	Neutral   []net.IPNet
}

//TODO: get rid of the switches
func ParseIPRange(ipexpr string, prefix int, ipr *IPRange) {
	if !strings.Contains(ipexpr, "/") {
		if strings.Contains(ipexpr, ":") {
			ipexpr = ipexpr + "/128"
		} else {
			ipexpr = ipexpr + "/32"
		}
	}

	arr := []net.IPNet{}

	switch prefix {
	case PASS:
		arr = ipr.Pass
	case FAIL:
		arr = ipr.Fail
	case SOFT_FAIL:
		arr = ipr.Soft_Fail
	case NEUTRAL:
		arr = ipr.Neutral
	}

	fmt.Printf("%+v", arr)

	_, net, err := net.ParseCIDR(ipexpr)
	handleError(err)

	arr = append(arr, *net)

	switch prefix {
	case PASS:
		ipr.Pass = arr
	case FAIL:
		ipr.Fail = arr
	case SOFT_FAIL:
		ipr.Soft_Fail = arr
	case NEUTRAL:
		ipr.Neutral = arr
	}

}
