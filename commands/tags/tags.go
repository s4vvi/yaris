package tags

import (
	"os"

	"yaris/utils"
)

func Run(args []string) {
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		runList(args[1:])
	case "update":
		runUpdate(args[1:])
	case "--help", "-h", "help":
		printUsage()
	default:
		utils.Errorf("unknown subcommand: %s", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	utils.PrintUsage("yaris tags <subcommand> [options] <rules-path>")
	utils.PrintRulesPathArg()
	utils.PrintSection("Subcommands")
	utils.PrintCommand("list", "list tags found in rules")
	utils.PrintCommand("update", "add or remove tags from rules")
}
