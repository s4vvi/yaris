package tags

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/VirusTotal/gyp"
	"yaris/utils"
)

func runUpdate(args []string) {
	fset := flag.NewFlagSet("tags update", flag.ExitOnError)
	tagsFlag := fset.String("t", "", "comma-separated tags to add")
	nameFilter := fset.String("n", "", "only update rules whose name contains this string (case insensitive)")
	fileFilter := fset.String("f", "", "only update rules whose file name contains this string (case insensitive)")

	fset.Usage = func() {
		utils.PrintUsage("yaris tags update [options] <rules-path>")
		utils.PrintRulesPathArg()
		utils.PrintSection("Options")
		fset.PrintDefaults()
	}

	if err := fset.Parse(args); err != nil {
		os.Exit(1)
	}

	if fset.NArg() == 0 {
		utils.Fatalf("rules path is required\n\nUsage: yaris tags update [options] <rules-path>")
	}
	if *tagsFlag == "" {
		utils.Fatalf("-t is required")
	}

	rulesPath := fset.Arg(0)

	var newTags []string
	for _, t := range strings.Split(*tagsFlag, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			newTags = append(newTags, t)
		}
	}

	info, err := os.Stat(rulesPath)
	if err != nil {
		utils.Fatalf("path error: %v", err)
	}
	singleFile := !info.IsDir()

	files, err := utils.WalkYaraFiles(rulesPath)
	if err != nil {
		utils.Fatalf("failed to walk rules path: %v", err)
	}
	if len(files) == 0 {
		utils.Fatalf("no .yar/.yara files found in: %s", rulesPath)
	}

	for _, file := range files {
		if err := updateFile(file, newTags, *nameFilter, *fileFilter); err != nil {
			if singleFile {
				utils.Fatalf("failed to update %s: %v", file, err)
			}
			utils.Errorf("failed to update %s: %v", file, err)
		}
	}
}

func updateFile(path string, newTags []string, nameFilter, fileFilter string) error {
	if fileFilter != "" {
		if !strings.Contains(strings.ToLower(filepath.Base(path)), strings.ToLower(fileFilter)) {
			return nil
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	ruleset, err := gyp.Parse(f)
	f.Close()
	if err != nil {
		return err
	}

	for _, rule := range ruleset.Rules {
		if nameFilter != "" {
			if !strings.Contains(strings.ToLower(rule.Identifier), strings.ToLower(nameFilter)) {
				continue
			}
		}
		rule.Tags = mergeTags(rule.Tags, newTags)
	}

	// Write to a buffer first; only touch the file if serialization succeeds.
	var buf bytes.Buffer
	if err := ruleset.WriteSource(&buf); err != nil {
		return err
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), info.Mode())
}

// mergeTags appends tags that are not already present (case-insensitive dedup).
func mergeTags(existing, toAdd []string) []string {
	set := make(map[string]bool, len(existing))
	for _, t := range existing {
		set[strings.ToLower(t)] = true
	}
	result := existing
	for _, t := range toAdd {
		if !set[strings.ToLower(t)] {
			result = append(result, t)
			set[strings.ToLower(t)] = true
		}
	}
	return result
}
