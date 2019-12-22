package main

import (
	"aws-credential-tool/ui"
	"fmt"
)

func main() {
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
