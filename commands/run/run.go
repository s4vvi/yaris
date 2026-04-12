package run

import (
	"encoding/hex"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	compiler, err := yara.NewCompiler()
	if err != nil {
		utils.Fatalf("failed to create YARA compiler: %v", err)
	}

	for _, f := range yaraFiles {
		if *verbose {
			fmt.Printf("%s%s%s\n", utils.ColorCyan, f, utils.ColorReset)
		}
		fh, err := os.Open(f)
		if err != nil {
			if singleFile {
				utils.Fatalf("failed to open %s: %v", f, err)
			}
			utils.Errorf("failed to open %s: %v", f, err)
			continue
		}
		addErr := compiler.AddFile(fh, "")
		fh.Close()
		if addErr != nil {
			if singleFile {
				utils.Fatalf("failed to compile %s: %v", f, addErr)
			}
			utils.Errorf("failed to compile %s: %v", f, addErr)
			continue
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		utils.Fatalf("failed to get compiled rules: %v", err)
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
		excludeSet: excludeSet,
		includeSet: includeSet,
		showOffset: *showOffset,
		showHex:    *showHex,
		hexLen:     *hexLen,
	}

	if targetInfo.IsDir() {
		_ = filepath.WalkDir(targetPath, func(path string, d iofs.DirEntry, err error) error {
			if err != nil {
				utils.Errorf("%v", err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			scanFile(rules, path, opts)
			return nil
		})
	} else {
		scanFile(rules, targetPath, opts)
	}
}

type scanOpts struct {
	excludeSet map[string]bool
	includeSet map[string]bool
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
		if opts.excludeSet != nil && hasAnyTag(match.Tags, opts.excludeSet) {
			continue
		}
		if opts.includeSet != nil && !hasAnyTag(match.Tags, opts.includeSet) {
			continue
		}

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

func hasAnyTag(tags []string, set map[string]bool) bool {
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
