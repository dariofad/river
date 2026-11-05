package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/dariofad/river/manifest"
	"gopkg.in/yaml.v3"
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
	case "repair":
		err = runRepair(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "  river-manifest generate --binary <ELF> --output <manifest.yaml|->")
	fmt.Fprintln(os.Stderr, "  river-manifest repair --manifest <manifest.yaml|-> [--models-dir <dir>] [--binary <ELF>] [--output <manifest.yaml|->]")
}

func writeManifestOutput(output string, m *manifest.Manifest) error {
	if output == "-" {
		raw, err := yaml.Marshal(m)
		if err != nil {
			return fmt.Errorf("encode manifest: %w", err)
		}
		if _, err := os.Stdout.Write(raw); err != nil {
			return fmt.Errorf("write manifest to stdout: %w", err)
		}
		return nil
	}
	if err := manifest.Write(output, m); err != nil {
		return err
	}
	log.Printf("wrote %s", output)
	return nil
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	binary := fs.String("binary", "", "target ELF executable")
	output := fs.String("output", "", "output YAML manifest path, or - for stdout")
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
	return writeManifestOutput(*output, m)
}

func runRepair(args []string) error {
	fs := flag.NewFlagSet("repair", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "input YAML manifest path, or - for stdin")
	modelsDir := fs.String("models-dir", os.Getenv("MODELS_DIR"), "path to the models directory (defaults to $MODELS_DIR)")
	binary := fs.String("binary", "", "explicit target ELF executable override")
	output := fs.String("output", "-", "output YAML manifest path, or - for stdout")
	_ = fs.Parse(args)
	if *manifestPath == "" {
		fs.Usage()
		return fmt.Errorf("--manifest is required")
	}
	var m *manifest.Manifest
	if *manifestPath == "-" {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read manifest from stdin: %w", err)
		}
		var parsed manifest.Manifest
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			return fmt.Errorf("parse manifest: %w", err)
		}
		m = &parsed
	} else {
		var err error
		m, err = manifest.Read(*manifestPath)
		if err != nil {
			return err
		}
	}
	if err := manifest.Repair(m, *modelsDir, *binary); err != nil {
		return err
	}
	return writeManifestOutput(*output, m)
}
