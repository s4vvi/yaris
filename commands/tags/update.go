package tags

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
	"yaris/utils"
)

type updateOptions struct {
	newTags     []string
	removeTags  []string
	removeAll   bool
	nameFilter  string
	fileFilter  string
	// scanContext, when non-empty, restricts -t additions to rules whose
	// scan_context meta attribute contains this value (case-insensitive).
	scanContext string
}

func runUpdate(args []string) {
	fset := flag.NewFlagSet("tags update", flag.ExitOnError)
	tagsFlag := fset.String("t", "", "comma-separated tags to add")
	nameFilter := fset.String("n", "", "only update rules whose name contains this string (case insensitive)")
	fileFilter := fset.String("f", "", "only update rules whose file name contains this string (case insensitive)")
	removeAllFlag := fset.Bool("remove-all", false, "remove all tags from matching rules")
	removeFlag := fset.String("remove", "", "comma-separated tags to remove from matching rules")
	contextFlag := fset.String("c", "", "only add -t tags to rules whose scan_context meta contains this value (case insensitive)")

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
	if *tagsFlag == "" && !*removeAllFlag && *removeFlag == "" {
		utils.Fatalf("at least one of -t, --remove-all, or --remove is required")
	}

	rulesPath := fset.Arg(0)

	opts := updateOptions{
		removeAll:   *removeAllFlag,
		nameFilter:  *nameFilter,
		fileFilter:  *fileFilter,
		scanContext: strings.ToLower(strings.TrimSpace(*contextFlag)),
	}

	for _, t := range strings.Split(*tagsFlag, ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			opts.newTags = append(opts.newTags, t)
		}
	}
	for _, t := range strings.Split(*removeFlag, ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			opts.removeTags = append(opts.removeTags, t)
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
		if err := updateFile(file, opts); err != nil {
			if singleFile {
				utils.Fatalf("failed to update %s: %v", file, err)
			}
			utils.Errorf("failed to update %s: %v", file, err)
		}
	}
}

func updateFile(path string, opts updateOptions) error {
	if opts.fileFilter != "" {
		if !strings.Contains(strings.ToLower(filepath.Base(path)), strings.ToLower(opts.fileFilter)) {
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
		if opts.nameFilter != "" {
			if !strings.Contains(strings.ToLower(rule.Identifier), strings.ToLower(opts.nameFilter)) {
				continue
			}
		}

		if opts.removeAll {
			rule.Tags = nil
		} else if len(opts.removeTags) > 0 {
			rule.Tags = removeTags(rule.Tags, opts.removeTags)
		}

		if len(opts.newTags) > 0 {
			if opts.scanContext == "" || metaMatchesContext(rule.Meta, opts.scanContext) {
				rule.Tags = mergeTags(rule.Tags, opts.newTags)
			}
		}
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

// metaMatchesContext returns true when the rule's scan_context meta attribute
// contains wantContext as one of its comma-separated values (case-insensitive).
// wantContext must already be lowercase.
func metaMatchesContext(meta []*ast.Meta, wantContext string) bool {
	for _, m := range meta {
		if strings.ToLower(m.Key) != "scan_context" {
			continue
		}
		val, ok := m.Value.(string)
		if !ok {
			continue
		}
		for _, ctx := range strings.Split(val, ",") {
			if strings.ToLower(strings.TrimSpace(ctx)) == wantContext {
				return true
			}
		}
	}
	return false
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

// removeTags returns existing with any tag found in toRemove dropped
// (case-insensitive comparison).
func removeTags(existing, toRemove []string) []string {
	removeSet := make(map[string]bool, len(toRemove))
	for _, t := range toRemove {
		removeSet[strings.ToLower(t)] = true
	}
	result := existing[:0:0]
	for _, t := range existing {
		if !removeSet[strings.ToLower(t)] {
			result = append(result, t)
		}
	}
	return result
}
