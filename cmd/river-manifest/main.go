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
	case "compile":
		err = runCompile(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "  river-manifest compile --manifest <manifest.yaml> --binary <ELF> --output <config.json>")
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	binary := fs.String("binary", "", "Simulink-generated ELF executable")
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

func runCompile(args []string) error {
	fs := flag.NewFlagSet("compile", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "user-edited River YAML manifest")
	binary := fs.String("binary", "", "target Simulink-generated ELF executable")
	output := fs.String("output", "", "output simulator JSON configuration")
	_ = fs.Parse(args)
	if *manifestPath == "" || *binary == "" || *output == "" {
		fs.Usage()
		return fmt.Errorf("--manifest, --binary, and --output are required")
	}
	m, err := manifest.Read(*manifestPath)
	if err != nil {
		return err
	}
	config, err := manifest.CompileLegacy(m, *binary)
	if err != nil {
		return err
	}
	if err := manifest.WriteLegacyConfiguration(*output, config); err != nil {
		return err
	}
	log.Printf("wrote %s", *output)
	return nil
}
