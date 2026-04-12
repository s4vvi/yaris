package utils

import (
	"fmt"
	"strings"
)

func PrintBanner() {
	fmt.Printf("%syaris%s - YARA rule management tool\n\n", ColorBold, ColorReset)
}

func PrintUsage(usage string) {
	fmt.Printf("%sUsage:%s %s\n\n", ColorYellow, ColorReset, usage)
}

func PrintSection(label string) {
	fmt.Printf("%s%s:%s\n", ColorYellow, label, ColorReset)
}

func PrintSynopsis(synopsis string) {
	fmt.Printf("  %s\n\n", synopsis)
}

func PrintCommand(name, description string) {
	padding := strings.Repeat(" ", 9-len(name))
	fmt.Printf("  %s%s%s%s%s\n", ColorCyan, name, ColorReset, padding, description)
}

func PrintOption(name, description string) {
	padding := strings.Repeat(" ", 12-len(name))
	fmt.Printf("  %s%s%s%s%s\n", ColorCyan, name, ColorReset, padding, description)
}

func PrintRulesPathArg() {
	fmt.Printf("  rules-path: path to a .yar file or a directory of rules\n\n")
}

func PrintHelpHint() {
	fmt.Printf("\nRun %syaris <command> --help%s for command-specific options.\n", ColorBold, ColorReset)
}

// PrintRuleLine prints a single rule in the format: path:name:TAG1,TAG2
// path is cyan, name is green, tags are red.
func PrintRuleLine(relPath, name string, tags []string) {
	tagStr := strings.Join(tags, ",")
	fmt.Printf("%s%s%s:%s%s%s:%s%s%s\n",
		ColorCyan, relPath, ColorReset,
		ColorGreen, name, ColorReset,
		ColorRed, tagStr, ColorReset,
	)
}

// PrintTagLine prints a single tag count line in the format: count:TAG
// count is cyan, tag is green.
func PrintTagLine(count int, tag string) {
	fmt.Printf("%s%d%s:%s%s%s\n",
		ColorCyan, count, ColorReset,
		ColorGreen, tag, ColorReset,
	)
}
