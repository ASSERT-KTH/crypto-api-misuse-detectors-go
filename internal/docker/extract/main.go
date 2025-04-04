package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// GopherResult represents the structure of the Gopher JSON output
type GopherResult struct {
	FuncName        string          `json:"FuncName"`
	Message         string          `json:"Message"`
	SlicingCriteria SlicingCriteria `json:"Slicing_Criteria"`
	DefUseLink      []DefUseLink    `json:"Def_Use_Link"`
	PredicateType   string          `json:"Predicate_Type"`
}

type SlicingCriteria struct {
	SourceCode     string `json:"SourceCode"`
	SourceFilename string `json:"SourceFilename"`
	SourceLineNum  int    `json:"SourceLineNum"`
	ParentFunction string `json:"ParentFunction"`
}

type DefUseLink struct {
	SourceCode     string `json:"SourceCode"`
	SourceFilename string `json:"SourceFilename"`
	SourceLineNum  int    `json:"SourceLineNum"`
	ParentFunction string `json:"ParentFunction"`
}

// ExtractedFunction contains the full function implementation and vulnerability context
type ExtractedFunction struct {
	FunctionName       string       `json:"function_name"`
	FilePath           string       `json:"file_path"`
	LineNumber         int          `json:"line_number"`
	FullImplementation string       `json:"full_implementation"`
	VulnerabilityInfo  GopherResult `json:"vulnerability_info"`
}

func main() {
	resultsFile := flag.String("results", "", "Path to gopher results JSON file")
	repoPath := flag.String("repo", "", "Path to repository directory")
	flag.Parse()

	if *resultsFile == "" || *repoPath == "" {
		fmt.Println("Error: Both -results and -repo flags are required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Since we're running inside the container, we know the paths will be correct
	if err := ExtractFunctions(*resultsFile, *repoPath); err != nil {
		fmt.Printf("Error extracting functions: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully extracted functions")
}

func ExtractFunctions(resultsFile, repoRootDir string) error {
	// Read and parse Gopher results
	jsonData, err := ioutil.ReadFile(resultsFile)
	if err != nil {
		return fmt.Errorf("reading results file: %w", err)
	}

	var results []GopherResult
	if err := json.Unmarshal(jsonData, &results); err != nil {
		return fmt.Errorf("parsing JSON: %w", err)
	}

	extractedFunctions := []ExtractedFunction{}

	// Process each finding
	for _, result := range results {
		sourcePath := result.SlicingCriteria.SourceFilename
		lineNum := result.SlicingCriteria.SourceLineNum
		parentFunc := result.SlicingCriteria.ParentFunction

		// Clean up the parent function name (remove parameter info)
		cleanFuncName := strings.Split(parentFunc, " ")[0]

		// Extract the function source code
		functionBody, err := extractFunction(repoRootDir, sourcePath, cleanFuncName, lineNum)
		if err != nil {
			fmt.Printf("Warning: Could not extract function %s from %s: %v\n",
				cleanFuncName, sourcePath, err)
			continue
		}

		extracted := ExtractedFunction{
			FunctionName:       cleanFuncName,
			FilePath:           sourcePath,
			LineNumber:         lineNum,
			FullImplementation: functionBody,
			VulnerabilityInfo:  result,
		}
		extractedFunctions = append(extractedFunctions, extracted)
	}

	// Write the output
	outputJson, err := json.MarshalIndent(extractedFunctions, "", "  ")
	if err != nil {
		return fmt.Errorf("creating output JSON: %w", err)
	}
	// TODO move to
	outputPath := "/analysis/repo/scan_results/gopher_analysis_with_samples.json"
	if err := ioutil.WriteFile(outputPath, outputJson, 0644); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}

	fmt.Printf("Successfully extracted %d functions to %s\n", len(extractedFunctions), outputPath)
	return nil
}

// extractFunction finds and extracts a complete function implementation
func extractFunction(repoRoot, filePath, functionName string, lineNum int) (string, error) {
	// Ensure filePath is absolute and points to the correct location in the container
	absFilePath := filePath
	if !strings.HasPrefix(filePath, "/analysis/repo") {
		// If the path doesn't start with the container repo path, add it
		absFilePath = filepath.Join("/analysis/repo", strings.TrimPrefix(filePath, "/"))
	}

	// Parse the file
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, absFilePath, nil, parser.ParseComments)
	if err != nil {
		return "", fmt.Errorf("parse error: %s (path: %s)", err, absFilePath)
	}

	// Look for the function
	var functionSrc string
	var found bool

	ast.Inspect(node, func(n ast.Node) bool {
		if found {
			return false // Stop if we already found it
		}

		// Check for function declarations
		if fn, ok := n.(*ast.FuncDecl); ok {
			if fn.Name.Name == functionName {
				// Get position info
				startPos := fset.Position(fn.Pos())
				endPos := fset.Position(fn.End())

				// If we have a line number, verify this is the right function
				// (in case of multiple functions with same name)
				if lineNum > 0 {
					if lineNum < startPos.Line || lineNum > endPos.Line {
						return true // Continue searching
					}
				}

				// Read the source code
				fileBytes, err := ioutil.ReadFile(absFilePath)
				if err != nil {
					return false
				}

				fileContent := string(fileBytes)
				lines := strings.Split(fileContent, "\n")

				// Extract the lines from start to end
				functionLines := lines[startPos.Line-1 : endPos.Line]
				functionSrc = strings.Join(functionLines, "\n")
				found = true
				return false
			}
		}

		// Methods on types can have complex names in the Gopher output
		// Handle method declarations where functionName might be something like "Type.Method"
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Recv != nil && len(fn.Recv.List) > 0 {
			// For methods, we need to construct typeName.methodName
			var typeName string

			// Extract the receiver type name
			switch t := fn.Recv.List[0].Type.(type) {
			case *ast.StarExpr:
				// Pointer receiver (*Type)
				if ident, ok := t.X.(*ast.Ident); ok {
					typeName = ident.Name
				}
			case *ast.Ident:
				// Value receiver (Type)
				typeName = t.Name
			}

			if typeName != "" {
				fullMethodName := typeName + "." + fn.Name.Name
				if fullMethodName == functionName || fn.Name.Name == functionName {
					// Get position info
					startPos := fset.Position(fn.Pos())
					endPos := fset.Position(fn.End())

					// If we have a line number, verify
					if lineNum > 0 {
						if lineNum < startPos.Line || lineNum > endPos.Line {
							return true // Continue searching
						}
					}

					// Read the source code
					fileBytes, err := ioutil.ReadFile(absFilePath)
					if err != nil {
						return false
					}

					fileContent := string(fileBytes)
					lines := strings.Split(fileContent, "\n")

					// Extract the lines from start to end
					functionLines := lines[startPos.Line-1 : endPos.Line]
					functionSrc = strings.Join(functionLines, "\n")
					found = true
					return false
				}
			}
		}

		return true
	})

	if !found {
		return "", fmt.Errorf("function %s not found", functionName)
	}

	return functionSrc, nil
}
