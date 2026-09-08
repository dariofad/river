package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/dariofad/river/manifest"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "generate":
		err = runGenerate(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  river-manifest generate --binary <ELF> --output <manifest.yaml>")
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	binary := fs.String("binary", "", "target ELF executable")
	output := fs.String("output", "", "output YAML manifest")
	_ = fs.Parse(args)
	if *binary == "" || *output == "" {
		fs.Usage()
		return fmt.Errorf("--binary and --output are required")
	}
	m, warnings, err := manifest.Generate(*binary)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		log.Printf("warning: %s", warning)
	}
	if err := manifest.Write(*output, m); err != nil {
		return err
	}
	log.Printf("wrote %s", *output)
	return nil
}
