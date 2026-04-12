package rules

import (
	"flag"
	"os"

	"yaris/utils"
)

func Run(args []string) {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)

	fs.Usage = func() {
		utils.PrintUsage("yaris rules <rules-path>")
		utils.PrintRulesPathArg()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if fs.NArg() == 0 {
		utils.Fatalf("rules path is required\n\nUsage: yaris rules <rules-path>")
	}

	rulesPath := fs.Arg(0)

	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		utils.Fatalf("path does not exist: %s", rulesPath)
	}

	files, err := utils.WalkYaraFiles(rulesPath)
	if err != nil {
		utils.Fatalf("%v", err)
	}

	for _, file := range files {
		rules, err := utils.ParseYaraFile(file)
		if err != nil {
			utils.Fatalf("failed to parse %s: %v", file, err)
		}
		relPath := utils.RelPath(rulesPath, file)
		for _, rule := range rules {
			utils.PrintRuleLine(relPath, rule.Name, rule.Tags)
		}
	}
}
