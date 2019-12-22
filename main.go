package main

import (
	"aws-credential-tool/ui"
)

func main() {
	u, err := ui.NewUI()
	if err != nil {
		panic(err)
	}
	if err := u.Run(); err != nil {
		panic(err)
	}
}
