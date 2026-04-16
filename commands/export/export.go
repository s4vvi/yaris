package export

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/VirusTotal/gyp"
	"yaris/utils"
)

func Run(args []string) {
	fset := flag.NewFlagSet("export", flag.ExitOnError)
	tagsFlag := fset.String("t", "", "comma-separated tags to filter rules by")
	output := fset.String("o", "", "output file path (defaults to stdout)")

	fset.Usage = func() {
		utils.PrintUsage("yaris export [options] <rules-path>")
		utils.PrintRulesPathArg()
		utils.PrintSection("Options")
		fset.PrintDefaults()
	}

	if err := fset.Parse(args); err != nil {
		os.Exit(1)
	}

	if fset.NArg() == 0 {
		utils.Fatalf("rules path is required\n\nUsage: yaris export -t <tags> <rules-path>")
	}

	rulesPath := fset.Arg(0)

	var filterTags []string
	for _, t := range strings.Split(*tagsFlag, ",") {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			filterTags = append(filterTags, t)
		}
	}

	var out io.Writer = os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			utils.Fatalf("failed to create output file: %v", err)
		}
		defer f.Close()
		out = f
	}

	yaraFiles, err := utils.WalkYaraFiles(rulesPath)
	if err != nil {
		utils.Fatalf("failed to walk rules path: %v", err)
	}

	writtenImports := map[string]bool{}
	for _, file := range yaraFiles {
		if err := exportFromFile(file, filterTags, writtenImports, out); err != nil {
			utils.Errorf("error processing %s: %v", file, err)
		}
	}
}

func exportFromFile(path string, filterTags []string, writtenImports map[string]bool, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	ruleset, err := gyp.Parse(f)
	if err != nil {
		return err
	}

	importsWritten := false
	for _, rule := range ruleset.Rules {
		if len(filterTags) > 0 && !hasMatchingTag(rule.Tags, filterTags) {
			continue
		}
		// Write new imports from this file on the first matching rule.
		if !importsWritten {
			for _, imp := range ruleset.Imports {
				if !writtenImports[imp] {
					fmt.Fprintf(out, "import \"%s\"\n", imp)
					writtenImports[imp] = true
				}
			}
			importsWritten = true
		}
		if err := rule.WriteSource(out); err != nil {
			utils.Errorf("failed to write rule %s: %v", rule.Identifier, err)
		}
	}
	return nil
}

func hasMatchingTag(tags []string, filterTags []string) bool {
	for _, t := range tags {
		if slices.Contains(filterTags, strings.ToLower(t)) {
			return true
		}
	}
	return false
}
