package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/VirusTotal/gyp"
)

// YaraRule holds parsed data for a single YARA rule.
type YaraRule struct {
	Name string
	Tags []string
}

// IsYaraExt returns true if the path ends with .yar or .yara.
func IsYaraExt(path string) bool {
	return strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara")
}

// WalkYaraFiles returns all .yar/.yara file paths under root.
// If root is a file it is returned directly (after extension check).
func WalkYaraFiles(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if !IsYaraExt(root) {
			return nil, &fs.PathError{Op: "open", Path: root, Err: fs.ErrInvalid}
		}
		return []string{root}, nil
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && IsYaraExt(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// ParseYaraFile parses a .yar/.yara file and returns its rules.
func ParseYaraFile(path string) ([]YaraRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ruleset, err := gyp.Parse(f)
	if err != nil {
		return nil, err
	}

	rules := make([]YaraRule, 0, len(ruleset.Rules))
	for _, r := range ruleset.Rules {
		rules = append(rules, YaraRule{
			Name: r.Identifier,
			Tags: r.Tags,
		})
	}
	return rules, nil
}

// RelPath returns path relative to base.
// If base is a file (not a directory), its parent directory is used as the base.
func RelPath(base, path string) string {
	info, err := os.Stat(base)
	baseDir := base
	if err == nil && !info.IsDir() {
		baseDir = filepath.Dir(base)
	}
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return path
	}
	return rel
}
