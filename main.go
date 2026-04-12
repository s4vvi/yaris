package main

import (
	"flag"
	"os"

	"yaris/commands/export"
	"yaris/commands/rules"
	"yaris/commands/run"
	"yaris/commands/tags"
	"yaris/utils"
)

func main() {
	top := flag.NewFlagSet("yaris", flag.ExitOnError)
	noColor := top.Bool("no-color", false, "disable colored output")
	top.Usage = printUsage

	top.Parse(os.Args[1:])

	if *noColor {
		utils.DisableColors()
	}

	args := top.Args()
	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "rules":
		rules.Run(args[1:])
	case "tags":
		tags.Run(args[1:])
	case "run":
		run.Run(args[1:])
	case "export":
		export.Run(args[1:])
	case "--help", "-h", "help":
		printUsage()
	default:
		utils.Errorf("unknown command: %s", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	utils.PrintBanner()
	utils.PrintSection("Usage")
	utils.PrintSynopsis("yaris [options] <command> [command options]")
	utils.PrintSection("Commands")
	utils.PrintCommand("rules", "list YARA rules")
	utils.PrintCommand("tags", "list or update tags on YARA rules")
	utils.PrintCommand("run", "run rules against a target directory")
	utils.PrintCommand("export", "export rules filtered by tags")
	utils.PrintSection("Options")
	utils.PrintOption("--no-color", "disable colored output")
	utils.PrintHelpHint()
}
