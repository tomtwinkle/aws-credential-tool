package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tomtwinkle/aws-credential-tool/io/profile"
	"github.com/tomtwinkle/aws-credential-tool/ui"
)

var version = "unknown"
var revision = "unknown"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "credential-process" {
		return runCredentialProcess(args[1:])
	}

	flags := flag.NewFlagSet("actool", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	showVersion := false
	flags.BoolVar(&showVersion, "v", false, "show application version")
	flags.BoolVar(&showVersion, "version", false, "show application version")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if showVersion {
		fmt.Printf("aws-credential-tool version %s.rev-%s\n", version, revision)
		return nil
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unknown command: %s", flags.Arg(0))
	}

	u, err := ui.NewUI()
	if err != nil {
		return err
	}

	return u.Run()
}

func runCredentialProcess(args []string) error {
	flags := flag.NewFlagSet("credential-process", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	profileName := ""
	flags.StringVar(&profileName, "profile", "", "AWS profile name")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}

	p, err := profile.NewProfile()
	if err != nil {
		return err
	}

	payload, err := p.CredentialProcessPayload(profileName)
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(payload)
	return err
}
