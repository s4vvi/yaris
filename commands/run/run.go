package run

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/VirusTotal/gyp"
	yara "github.com/hillu/go-yara/v4"
	"yaris/utils"
)

func Run(args []string) {
	fset := flag.NewFlagSet("run", flag.ExitOnError)
	verbose := fset.Bool("v", false, "print rule file paths as they are loaded")
	excludeTags := fset.String("e", "", "comma-separated tags to exclude")
	includeTags := fset.String("i", "", "comma-separated tags to include only")
	showOffset := fset.Bool("s", false, "show offset in file where match occurred")
	showHex := fset.Bool("x", false, "show hex dump at match offset")
	hexLen := fset.Int("l", 32, "hex dump length in bytes")
	batchSize := fset.Int("b", 100, "rule files to compile per scan pass; higher values use more memory but walk the target fewer times")

	fset.Usage = func() {
		utils.PrintUsage("yaris run [options] <rules-path> <target-path>")
		fmt.Println("  rules-path   path to a .yar file or directory of YARA rules")
		fmt.Println("  target-path  file or directory to scan")
		utils.PrintSection("Options")
		fset.PrintDefaults()
	}

	if err := fset.Parse(args); err != nil {
		os.Exit(1)
	}

	if fset.NArg() < 2 {
		utils.Fatalf("usage: yaris run [options] <rules-path> <target-path>")
	}

	rulesPath := fset.Arg(0)
	targetPath := fset.Arg(1)

	// Walk and compile YARA rules
	rulesInfo, err := os.Stat(rulesPath)
	if err != nil {
		utils.Fatalf("rules path error: %v", err)
	}
	singleFile := !rulesInfo.IsDir()

	yaraFiles, err := utils.WalkYaraFiles(rulesPath)
	if err != nil {
		utils.Fatalf("failed to walk rules path: %v", err)
	}
	if len(yaraFiles) == 0 {
		utils.Fatalf("no .yar/.yara files found in: %s", rulesPath)
	}

	if *batchSize < 1 {
		utils.Fatalf("-b must be at least 1")
	}

	// Parse tag filters
	excludeSet := parseTagSet(*excludeTags)
	includeSet := parseTagSet(*includeTags)

	// Scan target
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		utils.Fatalf("target path error: %v", err)
	}

	opts := scanOpts{
		showOffset: *showOffset,
		showHex:    *showHex,
		hexLen:     *hexLen,
	}

	// Process rule files in batches.  Each batch is compiled, used to scan
	// all targets, then discarded before the next batch is loaded.  This caps
	// resident memory to at most batchSize compiled rulesets at a time, at the
	// cost of walking the target tree once per batch.
	// Default batch size is 100
	totalCompiled := 0
	for batchStart := 0; batchStart < len(yaraFiles); batchStart += *batchSize {

		batchEnd := batchStart + *batchSize
		batchEnd = min(batchEnd, len(yaraFiles))

		var batch []*yara.Rules
		for _, f := range yaraFiles[batchStart:batchEnd] {
			if *verbose {
				fmt.Printf("%s%s%s\n", utils.ColorCyan, f, utils.ColorReset)
			}
			compiled, err := compileFile(f, includeSet, excludeSet)
			if err != nil {
				if singleFile {
					utils.Fatalf("failed to compile %s: %v", f, err)
				}
				utils.Errorf("failed to compile %s: %v", f, err)
				continue
			}
			if compiled == nil {
				// All rules in this file were filtered out by -i/-e; skip it.
				continue
			}
			batch = append(batch, compiled)
		}

		if len(batch) == 0 {
			continue
		}
		totalCompiled += len(batch)

		if targetInfo.IsDir() {
			_ = filepath.WalkDir(targetPath, func(path string, d iofs.DirEntry, err error) error {
				if err != nil {
					utils.Errorf("%v", err)
					return nil
				}
				if d.IsDir() {
					return nil
				}
				for _, rules := range batch {
					scanFile(rules, path, opts)
				}
				return nil
			})
		} else {
			for _, rules := range batch {
				scanFile(rules, targetPath, opts)
			}
		}

		// Explicitly free C-side memory for each compiled ruleset.  Go's GC
		// only tracks the tiny Go wrapper object, not the libyara C heap
		// allocation it points to, so finalizers run far too infrequently to
		// prevent accumulation.  Calling Destroy() here releases the C memory
		// immediately after each batch is no longer needed.
		for _, rules := range batch {
			rules.Destroy()
		}
	}

	if totalCompiled == 0 {
		utils.Fatalf("no rules compiled successfully")
	}
}

type scanOpts struct {
	showOffset bool
	showHex    bool
	hexLen     int
}

func scanFile(rules *yara.Rules, path string, opts scanOpts) {
	var matches yara.MatchRules
	if err := rules.ScanFile(path, 0, 30*time.Second, &matches); err != nil {
		utils.Errorf("scan error on %s: %v", path, err)
		return
	}

	for _, match := range matches {
		fmt.Printf("%s%s%s:%s%s%s\n",
			utils.ColorCyan, path, utils.ColorReset,
			utils.ColorRed, match.Rule, utils.ColorReset,
		)

		if opts.showOffset || opts.showHex {
			for _, ms := range match.Strings {
				offset := ms.Base + ms.Offset
				if opts.showOffset {
					fmt.Printf("  offset: 0x%x (%d) (%s)\n", offset, offset, ms.Name)
				}
				if opts.showHex {
					data, err := readBytes(path, int64(offset), opts.hexLen)
					if err == nil {
						fmt.Printf("  hex dump at 0x%x (%s):\n%s", offset, ms.Name, hex.Dump(data))
					}
				}
			}
		}
	}
}

func parseTagSet(csv string) map[string]bool {
	if csv == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, t := range strings.Split(csv, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			set[t] = true
		}
	}
	return set
}

// compileFile parses path, applies tag filters, and compiles the surviving
// rules into a ready-to-use Rules set.
//
// When includeSet or excludeSet are non-nil the file is first parsed with gyp
// so that individual rules can be filtered by their tags before any C-side
// compilation happens — avoiding wasted work on rules that would never match.
// Rules with no tags are excluded when includeSet is active.
//
// Returns (nil, nil) when tag filtering leaves zero rules to compile.
//
// Each file gets its own Compiler so a parse error in one file cannot poison
// compilation of any other (go-yara's Compiler is permanently unusable after
// the first parse error).
//
// Common external variables used by signature-base rulesets are pre-declared
// as empty strings so rules referencing them compile without "undefined
// identifier" errors.
func compileFile(path string, includeSet, excludeSet map[string]bool) (*yara.Rules, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	// Compiler holds its own C-side allocation separate from the Rules it
	// produces; destroy it explicitly once we have the Rules.
	defer c.Destroy()

	c.DefineVariable("filepath", "")
	c.DefineVariable("filename", "")
	c.DefineVariable("extension", "")
	c.DefineVariable("filetype", "")
	c.DefineVariable("owner", "")

	if len(includeSet) > 0 || len(excludeSet) > 0 {
		fh, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		ruleset, err := gyp.Parse(fh)
		fh.Close()
		if err != nil {
			return nil, err
		}

		filtered := ruleset.Rules[:0]
		for _, rule := range ruleset.Rules {
			if len(excludeSet) > 0 && tagSetContainsAny(rule.Tags, excludeSet) {
				continue
			}
			if len(includeSet) > 0 && !tagSetContainsAny(rule.Tags, includeSet) {
				continue
			}
			filtered = append(filtered, rule)
		}
		ruleset.Rules = filtered

		if len(ruleset.Rules) == 0 {
			return nil, nil
		}

		var buf bytes.Buffer
		if err := ruleset.WriteSource(&buf); err != nil {
			return nil, err
		}
		if err := c.AddString(buf.String(), ""); err != nil {
			return nil, err
		}
	} else {
		fh, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer fh.Close()
		if err := c.AddFile(fh, ""); err != nil {
			return nil, err
		}
	}

	return c.GetRules()
}

func tagSetContainsAny(tags []string, set map[string]bool) bool {
	for _, t := range tags {
		if set[t] {
			return true
		}
	}
	return false
}

func readBytes(path string, offset int64, length int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	n, err := f.Read(buf)
	if n > 0 {
		return buf[:n], nil
	}
	return nil, err
}
