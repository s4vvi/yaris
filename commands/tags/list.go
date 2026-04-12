package tags

import (
	"flag"
	"os"
	"sort"
	"strings"

	"yaris/utils"
)

func runList(args []string) {
	fs := flag.NewFlagSet("tags list", flag.ExitOnError)

	fs.Usage = func() {
		utils.PrintUsage("yaris tags list <rules-path>")
		utils.PrintRulesPathArg()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() == 0 {
		utils.Fatalf("rules path is required\n\nUsage: yaris tags list <rules-path>")
	}

	rulesPath := fs.Arg(0)

	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		utils.Fatalf("path does not exist: %s", rulesPath)
	}

	files, err := utils.WalkYaraFiles(rulesPath)
	if err != nil {
		utils.Fatalf("%v", err)
	}

	counts := make(map[string]int)
	for _, file := range files {
		rules, err := utils.ParseYaraFile(file)
		if err != nil {
			utils.Fatalf("failed to parse %s: %v", file, err)
		}
		for _, rule := range rules {
			if len(rule.Tags) == 0 {
				counts["(unassigned)"]++
			} else {
				for _, tag := range rule.Tags {
					counts[strings.ToLower(tag)]++
				}
			}
		}
	}

	type entry struct {
		tag   string
		count int
	}
	sorted := make([]entry, 0, len(counts))
	for tag, count := range counts {
		sorted = append(sorted, entry{tag, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].tag < sorted[j].tag
	})

	for _, e := range sorted {
		utils.PrintTagLine(e.count, e.tag)
	}
}
