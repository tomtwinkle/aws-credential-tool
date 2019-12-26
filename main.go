package main

import (
	"flag"
	"fmt"
	"github.com/tomtwinkle/aws-credential-tool/ui"
)

var version = "unknown"
var revision = "unknown"

func main() {
	var showVersion = false
	flag.BoolVar(&showVersion, "v", false, "show application version")
	flag.BoolVar(&showVersion, "version", false, "show application version")
	flag.Parse()

	if showVersion {
		fmt.Println(fmt.Sprintf("aws-credential-tool version %s.rev-%s", version, revision))
	} else {
		u, err := ui.NewUI()
		if err != nil {
			fmt.Printf("%+v", err)
			panic(err)
		}
		if err := u.Run(); err != nil {
			fmt.Printf("%+v", err)
			panic(err)
		}
	}
}
