package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/dariofad/river/manifest"
)

//go:embed assets/export_river_descriptor.m
var matlabExporter []byte

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 || os.Args[1] != "generate" {
		fmt.Fprintln(os.Stderr, "usage: river-manifest generate --binary <ELF> --output <manifest.yaml>")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	binary := fs.String("binary", "", "Simulink-generated ELF executable")
	output := fs.String("output", "", "output YAML manifest")
	var descriptors stringList
	var descriptorJSONs stringList
	fs.Var(&descriptors, "codedescriptor", "Code Descriptor .dmr (repeatable; requires MATLAB exporter)")
	fs.Var(&descriptorJSONs, "descriptor-json", "pre-exported Code Descriptor JSON (repeatable)")
	_ = fs.Parse(os.Args[2:])
	if *binary == "" || *output == "" {
		fs.Usage()
		os.Exit(2)
	}
	m, err := manifest.Generate(*binary)
	if err != nil {
		log.Fatal(err)
	}
	descriptorPaths, err := absolutePaths(descriptors)
	if err != nil {
		log.Fatal(err)
	}
	descriptorJSONPaths, err := absolutePaths(descriptorJSONs)
	if err != nil {
		log.Fatal(err)
	}
	exports := make([]string, 0, len(descriptorPaths)+len(descriptorJSONPaths))
	for _, descriptor := range descriptorPaths {
		exported, cleanup, err := exportDMR(descriptor)
		if err != nil {
			log.Fatal(err)
		}
		exports = append(exports, exported)
		defer cleanup()
	}
	exports = append(exports, descriptorJSONPaths...)
	if len(exports) > 0 {
		if err := manifest.EnrichDescriptors(m, exports); err != nil {
			log.Fatal(err)
		}
		m.Artifact.DescriptorSources = append(descriptorPaths, descriptorJSONPaths...)
	}
	if err := manifest.Write(*output, m); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", *output)
}

func absolutePaths(paths []string) ([]string, error) {
	abs := make([]string, 0, len(paths))
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, fmt.Errorf("resolve descriptor path %q: %w", path, err)
		}
		abs = append(abs, absolute)
	}
	return abs, nil
}

type stringList []string

func (values *stringList) String() string { return fmt.Sprint([]string(*values)) }

func (values *stringList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("descriptor path cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func exportDMR(dmr string) (string, func(), error) {
	if filepath.Base(dmr) != "codedescriptor.dmr" {
		return "", func() {}, fmt.Errorf("--codedescriptor must point to codedescriptor.dmr")
	}
	tmp, err := os.MkdirTemp("", "river-descriptor-")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	script := filepath.Join(tmp, "river_export_descriptor.m")
	if err := os.WriteFile(script, matlabExporter, 0o600); err != nil {
		cleanup()
		return "", func() {}, err
	}
	out := filepath.Join(tmp, "descriptor.json")
	expression := "addpath(" + strconv.Quote(tmp) + "); river_export_descriptor(" + strconv.Quote(filepath.Dir(dmr)) + "," + strconv.Quote(out) + ")"
	cmd := exec.Command("matlab", "-batch", expression)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("export codedescriptor.dmr through MATLAB: %w", err)
	}
	return out, cleanup, nil
}
