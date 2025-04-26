package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: go run main.go <package>")
	}

	path := os.Args[1]

	if path == "" {
		log.Fatal("filename is nil")
	}

	if filepath.IsLocal(path) && !filepath.IsAbs(path) {
		// If the path is relative, make it absolute
		absPath, err := filepath.Abs(path)
		if err != nil {
			log.Fatalf("Error getting absolute path: %v", err)
		}
		path = absPath
	}

	path, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("Error getting absolute path: %v", err)
	}

	cfg := &packages.Config{
		Mode: packages.LoadAllSyntax,
		Dir:  path,
	}

	pkgs, _ := packages.Load(cfg, "./...")
	if err != nil {
		log.Fatalf("could not load packages: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		log.Fatal("package had errors")
	}

	program, ssaPkgs := ssautil.AllPackages(pkgs, ssa.SanityCheckFunctions)
	program.Build()

	for _, pkg := range ssaPkgs {
		fmt.Println("==== Package:", pkg.Pkg.Path(), "====")

		for _, mem := range pkg.Members {
			if fn, ok := mem.(*ssa.Function); ok {
				fmt.Printf("== %s ==\n\n", fn.String())
				// full SSA code for function
				fn.WriteTo(os.Stdout)
				fmt.Println()
			}
		}
	}
}
