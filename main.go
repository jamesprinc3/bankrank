package main

import (
	// dns "bankrank/dns"
	// email "bankrank/email"
	http "bankrank/http"
	"fmt"
	net "net/http"
	"os"
)

func throwError(err error) {
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
}

func main() {

	github := "https://github.com/"
	resp, err := net.Get(github)
	throwError(err)

	hpkp := http.ParseHPKP(resp)
	s_hpkp := http.ScoreHPKP(hpkp)

	hsts := http.ParseHSTS(resp)
	s_hsts := http.ScoreHSTS(hsts)

	//etc

	fmt.Printf("\n")
	fmt.Printf("hpkp: %+v\n", hpkp)
	fmt.Printf("score: %d\n", s_hpkp)

	fmt.Printf("hsts: %+v\n", hsts)
	fmt.Printf("score: %d\n", s_hsts)
}
