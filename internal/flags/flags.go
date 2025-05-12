package flags

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// TODO this is messy, use cli option instead like cobra

type Config struct {
	DatasetConfig *dataset.DatasetConfig
	DatasetPath   string
	ResultsDir    string
	Verbose       bool
	Parallelism   int
	Timeout       time.Duration
	DockerDir     string
}

func ParseFlags() (*Config, error) {
	vulnFlagSet := flag.NewFlagSet("vuln", flag.ExitOnError)
	moduleFlagSet := flag.NewFlagSet("module", flag.ExitOnError)

	// Shared flags
	verbose := vulnFlagSet.Bool("verbose", false, "Enable verbose output")
	parallel := vulnFlagSet.Int("parallel", 6, "Number of parallel operations for Docker Compose")
	dockerDir := vulnFlagSet.String("docker-dir", "internal/docker", "Directory for Docker files")
	analysisOutDir := vulnFlagSet.String("out-dir", "results", "Directory for storing analysis results")

	moduleFlagSet.BoolVar(verbose, "verbose", false, "Enable verbose output")
	moduleFlagSet.IntVar(parallel, "parallel", 6, "Number of parallel operations for Docker Compose")
	moduleFlagSet.StringVar(dockerDir, "docker-dir", "internal/docker", "Directory for Docker files")
	moduleFlagSet.String("out-dir", "results", "Directory for storing analysis results")

	// Vulnerability-specific flags
	severity := vulnFlagSet.String("severity", "", "Filter vulnerabilities by severity level")
	cwe := vulnFlagSet.String("cwe", "", "Filter vulnerabilities by CWE type")
	cve := vulnFlagSet.String("cve", "", "Filter vulnerabilities by CVE")

	// Module-specific flags
	moduleLimit := moduleFlagSet.Int("module-limit", 550, "Limit the number of modules")
	noArchived := moduleFlagSet.Bool("no-archived", true, "Exclude archived repos")
	noEducational := moduleFlagSet.Bool("no-educational", true, "Exclude educational repos")
	noOutOfDate := moduleFlagSet.Bool("no-out-of-date", true, "Exclude out-of-date repos")
	noIncomplete := moduleFlagSet.Bool("no-incomplete", true, "Exclude incomplete repos")

	// Parse subcommand
	if len(os.Args) < 2 {
		return nil, fmt.Errorf("expected 'vuln' or 'module' subcommand")
	}

	var dsConfig *dataset.DatasetConfig

	dsType, err := datasetTypeFromSubcommand(os.Args[1])
	if err != nil {
		return nil, fmt.Errorf("invalid subcommand: %s", os.Args[1])
	}
	switch dsType {
	case dataset.VulnerabilityDatasetType:
		vulnFlagSet.Parse(os.Args[2:])
		dsConfig = &dataset.DatasetConfig{
			VulnerabilityConfig: &dataset.VulnerabilityConfig{
				SeverityLevel: *severity,
				CWE:           *cwe,
				CVE:           *cve,
			},
			Type: dataset.VulnerabilityDatasetType,
		}
	case dataset.ModuleDatasetType:
		moduleFlagSet.Parse(os.Args[2:])
		dsConfig = &dataset.DatasetConfig{
			ModuleConfig: &dataset.ModuleConfig{
				Limit:             *moduleLimit,
				FilterArchived:    *noArchived,
				FilterEducational: *noEducational,
				FilterOutOfDate:   *noOutOfDate,
				FilterIncomplete:  *noIncomplete,
			},
			Type: dataset.ModuleDatasetType,
		}

	default:
		return nil, fmt.Errorf("unknown subcommand: %s", os.Args[1])
	}

	// positional argument (input file path)
	var inputArgs []string
	if os.Args[1] == "vuln" {
		inputArgs = vulnFlagSet.Args()
	} else {
		inputArgs = moduleFlagSet.Args()
	}

	if len(inputArgs) != 1 {
		return nil, fmt.Errorf("input file path is required")
	}

	datasetPath := inputArgs[0]
	_, err = os.Stat(datasetPath)
	if err != nil {
		return nil, fmt.Errorf("dataset path '%s' does not exist", datasetPath)
	}

	config := &Config{
		DatasetConfig: dsConfig,
		DatasetPath:   datasetPath,
		ResultsDir:    *analysisOutDir,
		Verbose:       *verbose,
		Parallelism:   *parallel,
		DockerDir:     *dockerDir,
	}

	return config, nil
}

func datasetTypeFromSubcommand(cmd string) (dataset.DatasetType, error) {
	switch cmd {
	case "vuln":
		return dataset.VulnerabilityDatasetType, nil
	case "module":
		return dataset.ModuleDatasetType, nil
	default:
		return "", fmt.Errorf("unknown subcommand: %s", cmd)
	}
}
