package dns

import (
    //"fmt"
    //"net"
    "testing"
    "reflect"
    "net"
    "math"
    // "time"
    //reflections "github.com/oleiade/reflections"
)

var NetworkSizeTests = []struct {
    mask []byte

    size int32
}{
    {mask: []byte{240, 0, 0, 0},
     size: 268435456,
    },
    {mask: []byte{192, 0, 0, 0},
     size: 1073741824,
    },
    {mask: []byte{255, 240, 0, 0},
     size: 1048576,
    },
    {mask: []byte{255, 255, 255, 255},
     size: 1,
    },
    // {mask: []byte{0, 0, 0, 0},
    //  size: math.MaxInt32,
    // },
}

func TestNetworkSize(t *testing.T) {
    for _, tt := range NetworkSizeTests {
        if s := networkSize(tt.mask); !(tt.size == s) {
            t.Errorf("NetworkSize was %i \n want %i\n", s, tt.size)
        }
    } 
}


var ScoreSPFTests = []struct {
    p *SPFProfile

    score float64
}{
    //IP4---------
    {p: &SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                  Mask: []byte{255, 255, 255, 255}}}}},
     score: 10,
    },
    {p: &SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                  Mask: []byte{255, 0, 0, 0}}}}},
     score: 3,
    },
    {p: &SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                  Mask: []byte{255, 240, 0, 0}}}}},
     score: 5,
    },
    {p: &SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                  Mask: []byte{255, 255, 0, 0}}}}},
     score: 6,
    },
    //A------------
    {p: &SPFProfile{A: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                Mask: []byte{255, 255, 0, 0}}}}},
     score: 6,
    },
    //MX-----------
    {p: &SPFProfile{MX: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                Mask: []byte{255, 255, 0, 0}}}}},
     score: 6,
    },
    //PTR ---------
    {p: &SPFProfile{Domain: "google.com", PTR: map[string]int{"google.com":PASS}},
     score: 10,
    },
    {p: &SPFProfile{Domain: "google.com", PTR: map[string]int{}},
     score: 0,
    },
    {p: &SPFProfile{Domain: "google.com", PTR: map[string]int{"example.com":PASS}},
     score: -10,
    },
    //EXISTS ------
    {p: &SPFProfile{Domain: "google.com", EXISTS: map[string]int{"google.com":PASS}},
     score: 10,
    },
    {p: &SPFProfile{Domain: "google.com", EXISTS: map[string]int{}},
     score: 0,
    },
    {p: &SPFProfile{Domain: "google.com", EXISTS: map[string]int{"example.com":PASS}},
     score: -10,
    },
    //INCLUDE -----
    {p: &SPFProfile{Domain: "google.com", INCLUDE: map[string]int{"google.com":PASS}},
     score: 10,
    },
    {p: &SPFProfile{Domain: "google.com", INCLUDE: map[string]int{}},
     score: 0,
    },
    {p: &SPFProfile{Domain: "google.com", INCLUDE: map[string]int{"example.com":PASS}},
     score: -10,
    },
    //Combos:
    {p: &SPFProfile{Domain: "google.com", PTR: map[string]int{"example.com":PASS},
                    IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                  Mask: []byte{255, 255, 255, 255}}}}},
     score: 0,
    },
    {p: &SPFProfile{Domain: "google.com", PTR: map[string]int{"google.com":PASS},
                    IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                  Mask: []byte{255, 255, 255, 255}}}}},
     score: 20,
    },
    // {p: &SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
    //                                                   Mask: []byte{0, 0, 0, 0}}}}},
    //  score: 31,
    // }, TODO: figure out how to handle zero mask

}

func TestScoreSPF(t *testing.T) {
    for _, tt := range ScoreSPFTests {
        if s := ScoreSPF(tt.p); !(math.Abs(tt.score - s) < 1) {
            t.Errorf("ScoreSPF was %i \n want %i\n", s, tt.score)
        }
    } 
}


//TODO: want these tests to have results like 1024 and 2048, actual public key lengths
var ScoreDKIMDNSTests = []struct {
    p *DKIMDNSProfile

    score int
}{
    {p: &DKIMDNSProfile{V:1, P:"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDoclZ4XpNdyh8fvXDbHKcVvp63pZX42ceid9R2FHT/UnG4dAtVcBWxzgxdThgSFYevgDkKC40Z1Kfj4kMeJxjdAl11Cbe//iArMdM3bmTJNP3FzFA82gwhE36jUGYawqWF1LcJXb0QH+khp/tRehMnFI4pRmvGGW/51yaazeBX6wIDAQAB"},
     score:162,
    },
    {p: &DKIMDNSProfile{V:1, T:map[string]bool{"y":true}, P:"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDoclZ4XpNdyh8fvXDbHKcVvp63pZX42ceid9R2FHT/UnG4dAtVcBWxzgxdThgSFYevgDkKC40Z1Kfj4kMeJxjdAl11Cbe//iArMdM3bmTJNP3FzFA82gwhE36jUGYawqWF1LcJXb0QH+khp/tRehMnFI4pRmvGGW/51yaazeBX6wIDAQAB"},
     score:0,
    },
    {p: &DKIMDNSProfile{V:1, P:"MIG"},
     score:0,
    },
}

func TestScoreDKIMDNS(t *testing.T) {
    for _, tt := range ScoreDKIMDNSTests {       

        if s := scoreDKIMDNS(tt.p); !reflect.DeepEqual(tt.score, s) {
            t.Errorf("ScoreDKIMDNS was %i \n want %i\n", s, tt.score)
        }
    } 
}


//WARNING: these tests require a lookup, they might break at a moment's notice for things out of our control
var ScoreDKIMTests = []struct {
    p *DKIMSigProfile

    score int
}{
    {p: &DKIMSigProfile{},
     score: 0,
    },
    {p: &DKIMSigProfile{V:1, A:"rsa-sha256", D:"information.natwest.com", C:"simple/simple", 
                          I:"@information.natwest.com", Q:"dns/txt", S:"mail", T:1462844746,
                          X:1494380746, H:[]string{"message-id", "date", "from", "to", "subject", "mime-version", "content-transfer-encoding"},
                          BH:"Vq/vP4CFQA5eYLaSAGG07LEMQiHvUQ53z2M5UvFlf3Q=",
                          B:`ooEK+zWITEXLRmoX6PX5sajrb4EkE4/tPYI5Afyeh6xrBfPshsCBCQ5TlkbZgrgq52gcM6SJq16IivSb2AA2IWY1Dr64xeP/MerZOpr2ZVrQh+fKNp9u3920oZtXbRlXtjIf8b5ZE3pwSFjZjzs/s+77EEUJR9L0jk7oigk0mG0=`},

     score: 162,
    },
    // {p: &DKIMSigProfile{V:1, D:"service.yoursantander.co.uk", S:"default"},
    //  score:0,
    // },
    // {p: &DKIMSigProfile{V:1, A: "a=rsa-sha1", D:"service.yoursantander.co.uk", S:"default"},
    //  score:0,
    // },
    {p: &DKIMSigProfile{V:1, A:"rsa-sha256", C:"relaxed/simple", D:"facebookmail.com",
                           S:"s1024-2013-q3", T:1464936932, BH:"0/SqN7q7PTfU5P2gbZVqBbFiMaMYEiQoGv3hXqkNeAI=",
                           H:[]string{"Date", "To", "Subject", "From", "MIME-Version", "Content-Type"},
                           B: `KrZF1OsprlblWjX1lBg7rhIZ444gb1/yUjF7vEfJ9YieFKVyjAoNOzCWCiRzFcaGP4o2u4QarTQOQ3SmBXse40DbyPaYjak0ZY5TtEjatx1XyuvQreVEXn47BH4ZFxLLHxm5cSG077uuCDCRP9eBwHNRRXLQVi5MLmLpRYu2H4o=`},
     score: 162,
    },
}

func TestScoreDKIM(t *testing.T) {

    for _, tt := range ScoreDKIMTests {       

        if s := ScoreDKIM(tt.p); !reflect.DeepEqual(tt.score, s) {
            t.Errorf("ScoreDKIM was %i \n want %i\n", s, tt.score)
        }
    }    

}


var ScoreDMARCTests = []struct {
    p *DMARCProfile

    score int
}{
    {p: &DMARCProfile{V:1, P: "reject", PCT:100, RUA:"mailto:postmaster@dmarcdomain.com", Domain: "dmarcdomain.com"},
     score: 2,
    },
}


func TestScoreDMARC(t *testing.T) {

    for _, tt := range ScoreDMARCTests {       

        if s := ScoreDMARC(tt.p); !reflect.DeepEqual(tt.score, s) {
            t.Errorf("ScoreDMARC was %i \n want %i\n", s, tt.score)
        }
    }    

}

var ParseParamsTests = []struct {
    record string

    result map[string]string
}{
    {record: `v=1`,
     result: map[string]string{"v":"1"}},
    {record: `v=1; a=rsa-sha256`,
     result: map[string]string{"v":"1", "a":"rsa-sha256"}},
    {record: `k=rsa;t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTTTpwACzQ78sZm9Eks9U/eZ2E6bttoIF1/Gac9JPfDktEWqdWQIJvMqov+rPdjBrUgmq7W2hLL8t8B7QyM7cwmFMnGWTkAiozNV9Afe7fIxSsZ9lJVtmBHHf3/kmcyrm+ul0CYqwhGP1g7NQstoTr6aeS0deehzIWHroIelNBRwIDAQAB`,
     result: map[string]string{"k":"rsa", "t":"y", "p":"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTTTpwACzQ78sZm9Eks9U/eZ2E6bttoIF1/Gac9JPfDktEWqdWQIJvMqov+rPdjBrUgmq7W2hLL8t8B7QyM7cwmFMnGWTkAiozNV9Afe7fIxSsZ9lJVtmBHHf3/kmcyrm+ul0CYqwhGP1g7NQstoTr6aeS0deehzIWHroIelNBRwIDAQAB"},
     },
}

func TestParseParams(t *testing.T) {

    for _, tt := range ParseParamsTests {       

        if r := parseParams(tt.record); !reflect.DeepEqual(tt.result, r) {
            t.Errorf("parseParams for %q = %q\n want %q\n", tt.result, r, tt.result)
        }
    }

}

var ParseDKIMDNSTests = []struct {
    record string

    result DKIMDNSProfile
}{
    {record: "k=rsa;t=y; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTTTpwACzQ78sZm9Eks9U/eZ2E6bttoIF1/Gac9JPfDktEWqdWQIJvMqov+rPdjBrUgmq7W2hLL8t8B7QyM7cwmFMnGWTkAiozNV9Afe7fIxSsZ9lJVtmBHHf3/kmcyrm+ul0CYqwhGP1g7NQstoTr6aeS0deehzIWHroIelNBRwIDAQAB",
     result: DKIMDNSProfile{K:"rsa", T:map[string]bool{"y":true}, P: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTTTpwACzQ78sZm9Eks9U/eZ2E6bttoIF1/Gac9JPfDktEWqdWQIJvMqov+rPdjBrUgmq7W2hLL8t8B7QyM7cwmFMnGWTkAiozNV9Afe7fIxSsZ9lJVtmBHHf3/kmcyrm+ul0CYqwhGP1g7NQstoTr6aeS0deehzIWHroIelNBRwIDAQAB"},   
    },
}

var ParseDMARCTests = []struct {
    record string
    domain string

    result DMARCProfile
}{
    {record: "v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@dmarcdomain.com",
    domain: "dmarcdomain.com",
    result: DMARCProfile{V:1, P: "reject", PCT:100, RUA:"mailto:postmaster@dmarcdomain.com", RF:"AFRF", RI:86400, FO:"0", Domain: "dmarcdomain.com"},
    },
    {record: "v=DMARC1;      p=reject;pct=100;     rua=mailto:postmaster@dmarcdomain.com",
    domain: "dmarcdomain.com",
    result: DMARCProfile{V:1, P: "reject", PCT:100, RUA:"mailto:postmaster@dmarcdomain.com", RF:"AFRF", RI:86400, FO:"0", Domain: "dmarcdomain.com"},
    }, //handle whitespace ^^
    {record: "v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com",
    domain: "google.com",
    result: DMARCProfile{V:1, P: "reject", PCT:100, RUA:"mailto:mailauth-reports@google.com", RF:"AFRF", RI:86400, FO:"0", Domain: "google.com"},
    },
    {record: "v=DMARC1; p=none; rua=mailto:dmarc@github.com",
    domain: "github.com",
    result: DMARCProfile{V:1, P: "none", PCT:100, RUA:"mailto:dmarc@github.com", RF:"AFRF", RI:86400, FO:"0", Domain: "github.com"},
    },
}


func TestParseDMARC(t *testing.T) {
    for _, tt := range ParseDMARCTests {  

        if p := ParseDMARC(tt.record, tt.domain); !reflect.DeepEqual(&tt.result, p) {
            t.Errorf("ParseDMARC was %q \n want %q\n", p, tt.result)
        }
    }
}

//TODO: try and refactor this struct, field is needed to reduce boiler plate n the struct delclarations
// (we would have to declare all the other fields as null fields for the tests to Pass)
var ParseMechanismTests = []struct {
    mech string
    field string
    IP string

    result SPFProfile
}{
    {mech: "+ip4:192.168.0.1",
     field: "ip4",
     result: SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                      Mask: []byte{255, 255, 255, 255}}}}},
    },
    {mech: "-ip4:192.168.0.1",
     field: "ip4",
     result: SPFProfile{IP4: IPRange{Fail: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                      Mask: []byte{255, 255, 255, 255}}}}},
    },
    {mech: "?ip4:192.168.0.1",
     field: "ip4",
     result: SPFProfile{IP4: IPRange{Neutral: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                         Mask: []byte{255, 255, 255, 255}}}}},
    },
    {mech: "~ip4:192.168.0.1",
     field: "ip4",
     result: SPFProfile{IP4: IPRange{Soft_Fail: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                                      Mask: []byte{255, 255, 255, 255}}}}},
    },
    {mech: "+ip4:192.168.0.1/31",
     field: "ip4",
     result: SPFProfile{IP4: IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 0},
                                                      Mask: []byte{255, 255, 255, 254}}}}},
    },
    {mech: "+ip6:1080::8:800:200C:417A",
     field: "ip6",
     result: SPFProfile{IP6: IPRange{Pass: []net.IPNet{{IP: []byte{16, 128, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0, 32, 12, 65, 122},
                                                      Mask: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}}}}},
    },
    {mech: "+ip6:1080::8:800:200C:417A/127",
     field: "ip6",
     result: SPFProfile{IP6: IPRange{Pass: []net.IPNet{{IP: []byte{16, 128, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0, 32, 12, 65, 122},
                                                      Mask: []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254}}}}},
    },
    {mech: "a",
     IP: "127.0.0.1",
     field: "a",
     result: SPFProfile{IP:"127.0.0.1", 
                         A: IPRange{Pass: []net.IPNet{{IP: []byte{127, 0, 0, 1},
                                                     Mask: []byte{255, 255, 255, 255}}}}},
    },
    {mech: "a/31",
     IP: "127.0.0.1",
     field: "a",
     result: SPFProfile{IP:"127.0.0.1", 
                         A: IPRange{Pass: []net.IPNet{{IP: []byte{127, 0, 0, 0},
                                                     Mask: []byte{255, 255, 255, 254}}}}},
    },
    {mech: "-a/31",
     IP: "127.0.0.1",
     field: "a",
     result: SPFProfile{IP:"127.0.0.1", 
                         A: IPRange{Fail: []net.IPNet{{IP: []byte{127, 0, 0, 0},
                                                     Mask: []byte{255, 255, 255, 254}}}}},
    },
    // {mech: "a:example.com",
    //  IP: "0.0.0.0",
    //  field: "a",
    //  result: SPFProfile{a: map[string]int{"example.com": PASS}},
    // }, //TODO: decide whether to store just IP addresses or domain names
}

//TODO: way more tests ^^
func TestParseMechanism(t *testing.T) {

    for _, tt := range ParseMechanismTests {

        p := SPFProfile{IP: tt.IP}

        switch tt.field {
            case "IP4": p.IP4 = IPRange{}
            case "IP6": p.IP6 = IPRange{}
            case "A"  : p.A = IPRange{}
        }        

        if ParseMechanism(tt.mech, &p); !reflect.DeepEqual(tt.result, p) {
            t.Errorf("ParseMechanism was %q \n want %q\n", p, tt.result)
        }
    }

}

var ParseIPRangeTests = []struct {
    ipexpr string
    prefix int

    result *IPRange
}{
    {ipexpr: "192.168.0.1/32",
     prefix: PASS,
     result: &IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                      Mask: []byte{255, 255, 255, 255}}}},
    },
    {ipexpr: "192.168.0.1/32",
     prefix: FAIL,
     result: &IPRange{Fail: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                      Mask: []byte{255, 255, 255, 255}}}},
    },
    {ipexpr: "192.168.0.1/32",
     prefix: NEUTRAL,
     result: &IPRange{Neutral: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                      Mask: []byte{255, 255, 255, 255}}}},
    },
    {ipexpr: "192.168.0.1/32",
     prefix: SOFT_FAIL,
     result: &IPRange{Soft_Fail: []net.IPNet{{IP: []byte{192, 168, 0, 1},
                                      Mask: []byte{255, 255, 255, 255}}}},
    },
    {ipexpr: "192.168.0.1/31",
     prefix: PASS,
     result: &IPRange{Pass: []net.IPNet{{IP: []byte{192, 168, 0, 0},
                                      Mask:  []byte{255, 255, 255, 254}}}},
    },
    {ipexpr: "192.168.0.1/31",
     prefix: FAIL,
     result: &IPRange{Fail: []net.IPNet{{IP: []byte{192, 168, 0, 0},
                                      Mask:  []byte{255, 255, 255, 254}}}},
    },
    {ipexpr: "1080::8:800:200C:417A",
     prefix: PASS,
     result: &IPRange{Pass: []net.IPNet{{IP: []byte{16, 128, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0, 32, 12, 65, 122},
                                      Mask:  []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}}}},
    },
}

func TestParseIPRange(t *testing.T) {

    for _, tt := range ParseIPRangeTests {   

        ipr := &IPRange{}    

        if ParseIPRange(tt.ipexpr, tt.prefix, ipr); !reflect.DeepEqual(tt.result, ipr) {
            t.Errorf("ParseIPRange2 was %i \n want %i\n", ipr, tt.result)
        }
    } 
}
