package utils

import (
	"fmt"
	"os"
)

var (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

// DisableColors zeroes all color variables so subsequent output is plain text.
func DisableColors() {
	ColorReset = ""
	ColorRed = ""
	ColorGreen = ""
	ColorYellow = ""
	ColorBlue = ""
	ColorCyan = ""
	ColorBold = ""
}

func Debugf(format string, args ...any) {
	fmt.Printf(ColorBlue+"[debug]"+ColorReset+" "+format+"\n", args...)
}

func Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, ColorRed+"[error]"+ColorReset+" "+format+"\n", args...)
}

func Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, ColorRed+"[error]"+ColorReset+" "+format+"\n", args...)
	os.Exit(1)
}
