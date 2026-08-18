package seal

import (
	"go/build"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNoForbiddenNetworkImports walks every first-party (kosh/...) package and
// fails if any of them import a forbidden networking package. This enforces the
// network air-seal documented in docs/SECURITY_ISOLATION.md.
func TestNoForbiddenNetworkImports(t *testing.T) {
	root := repoRoot(t)

	forbidden := map[string]bool{}
	for _, f := range ForbiddenImports {
		forbidden[f] = true
	}

	pkgDirs := firstPartyPackageDirs(t, root)
	if len(pkgDirs) == 0 {
		t.Fatal("no first-party packages discovered")
	}

	ctx := build.Default
	for _, dir := range pkgDirs {
		pkg, err := ctx.ImportDir(dir, 0)
		if err != nil {
			// Directories without buildable Go files for this platform are skipped.
			if _, ok := err.(*build.NoGoError); ok {
				continue
			}
			t.Fatalf("import %s: %v", dir, err)
		}
		imports := append([]string{}, pkg.Imports...)
		imports = append(imports, pkg.TestImports...)
		imports = append(imports, pkg.XTestImports...)

		for _, imp := range imports {
			if forbidden[imp] {
				t.Errorf("package %q imports forbidden network package %q (breaks air-seal)", pkg.ImportPath, imp)
			}
			for _, pre := range ForbiddenPrefixes {
				if strings.HasPrefix(imp, pre) {
					t.Errorf("package %q imports forbidden network family %q (breaks air-seal)", pkg.ImportPath, imp)
				}
			}
		}
	}
}

// repoRoot returns the module root directory (one level up from internal/seal).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve caller path")
	}
	// thisFile = <root>/internal/seal/seal_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

// firstPartyPackageDirs returns directories under the module root that contain Go
// source, excluding vendor and dot-directories.
func firstPartyPackageDirs(t *testing.T, root string) []string {
	t.Helper()
	var dirs []string
	seen := map[string]bool{}

	for _, sub := range []string{"cmd", "internal"} {
		base := filepath.Join(root, sub)
		walk(base, func(dir string) {
			if seen[dir] {
				return
			}
			seen[dir] = true
			dirs = append(dirs, dir)
		})
	}
	return dirs
}

// walk visits dir and all subdirectories, calling fn for each directory that exists.
func walk(dir string, fn func(string)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // directory may not exist (e.g. no cmd/ yet) — that's fine
	}
	fn(dir)
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && e.Name() != "vendor" {
			walk(filepath.Join(dir, e.Name()), fn)
		}
	}
}
