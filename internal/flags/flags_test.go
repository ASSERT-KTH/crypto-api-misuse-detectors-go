package flags

import (
	"os"
	"testing"
	"time"

	"github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// Test parsing of default flags for the 'vuln' subcommand
func TestParseFlagsVulnDefault(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cmd", "vuln", "input.json"}
	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DatasetPath != "input.json" {
		t.Errorf("expected DatasetPath 'input.json', got %q", cfg.DatasetPath)
	}
	if cfg.DatasetConfig == nil {
		t.Fatal("DatasetConfig is nil")
	}
	if cfg.DatasetConfig.Type != dataset.VulnerabilityDatasetType {
		t.Errorf("expected Type %v, got %v", dataset.VulnerabilityDatasetType, cfg.DatasetConfig.Type)
	}
	if cfg.DatasetConfig.VulnerabilityConfig == nil {
		t.Fatal("VulnerabilityConfig is nil")
	}
	vcfg := cfg.DatasetConfig.VulnerabilityConfig
	if vcfg.SeverityLevel != "" {
		t.Errorf("expected default SeverityLevel '', got %q", vcfg.SeverityLevel)
	}
	if vcfg.CWE != "" {
		t.Errorf("expected default CWE '', got %q", vcfg.CWE)
	}
	if vcfg.CVE != "" {
		t.Errorf("expected default CVE '', got %q", vcfg.CVE)
	}
	if cfg.Verbose != true {
		t.Errorf("expected default Verbose true, got %v", cfg.Verbose)
	}
	if cfg.Parallelism != 4 {
		t.Errorf("expected default Parallelism 4, got %d", cfg.Parallelism)
	}
	if cfg.Timeout != 1*time.Minute {
		t.Errorf("expected default Timeout 1m, got %v", cfg.Timeout)
	}
	if cfg.DockerDir != "internal/docker" {
		t.Errorf("expected default DockerDir 'internal/docker', got %q", cfg.DockerDir)
	}
	if cfg.DatasetConfig.ModuleConfig != nil {
		t.Errorf("expected ModuleConfig nil for vuln, got %v", cfg.DatasetConfig.ModuleConfig)
	}
}

// Test parsing of custom flags for the 'vuln' subcommand
func TestParseFlagsVulnCustom(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{
		"cmd", "vuln",
		"--verbose=false",
		"--parallel=10",
		"--docker-dir=/tmp/docker",
		"--severity=high",
		"--cwe=CWE-123",
		"--cve=CVE-2022-XXXX",
		"file.json",
	}
	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.Verbose != false {
		t.Errorf("expected Verbose false, got %v", cfg.Verbose)
	}
	if cfg.Parallelism != 10 {
		t.Errorf("expected Parallelism 10, got %d", cfg.Parallelism)
	}

	if cfg.DockerDir != "/tmp/docker" {
		t.Errorf("expected DockerDir '/tmp/docker', got %q", cfg.DockerDir)
	}
	vcfg := cfg.DatasetConfig.VulnerabilityConfig
	if vcfg.SeverityLevel != "high" {
		t.Errorf("expected SeverityLevel 'high', got %q", vcfg.SeverityLevel)
	}
	if vcfg.CWE != "CWE-123" {
		t.Errorf("expected CWE 'CWE-123', got %q", vcfg.CWE)
	}
	if vcfg.CVE != "CVE-2022-XXXX" {
		t.Errorf("expected CVE 'CVE-2022-XXXX', got %q", vcfg.CVE)
	}
}

// Test parsing of default flags for the 'module' subcommand
func TestParseFlagsModuleDefault(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cmd", "module", "data.csv"}
	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DatasetPath != "data.csv" {
		t.Errorf("expected DatasetPath 'data.csv', got %q", cfg.DatasetPath)
	}
	if cfg.DatasetConfig.Type != dataset.ModuleDatasetType {
		t.Errorf("expected Type %v, got %v", dataset.ModuleDatasetType, cfg.DatasetConfig.Type)
	}
	mcfg := cfg.DatasetConfig.ModuleConfig
	if mcfg == nil {
		t.Fatal("ModuleConfig is nil")
	}
	if mcfg.Limit != 550 {
		t.Errorf("expected default Limit 550, got %d", mcfg.Limit)
	}
	if !mcfg.FilterArchived {
		t.Errorf("expected default FilterArchived true, got %v", mcfg.FilterArchived)
	}
	if !mcfg.FilterEducational {
		t.Errorf("expected default FilterEducational true, got %v", mcfg.FilterEducational)
	}
	if !mcfg.FilterOutOfDate {
		t.Errorf("expected default FilterOutOfDate true, got %v", mcfg.FilterOutOfDate)
	}
	if !mcfg.FilterIncomplete {
		t.Errorf("expected default FilterIncomplete true, got %v", mcfg.FilterIncomplete)
	}
}

// Test parsing of custom flags for the 'module' subcommand
func TestParseFlagsModuleCustom(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{
		"cmd", "module",
		"--verbose=false",
		"--parallel=2",
		"--docker-dir=/docker",
		"--module-limit=10",
		"--no-archived=false",
		"--no-educational=false",
		"--no-out-of-date=false",
		"--no-incomplete=false",
		"mods.csv",
	}
	cfg, err := ParseFlags()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.Verbose != false {
		t.Errorf("expected Verbose false, got %v", cfg.Verbose)
	}
	if cfg.Parallelism != 2 {
		t.Errorf("expected Parallelism 2, got %d", cfg.Parallelism)
	}
	if cfg.DockerDir != "/docker" {
		t.Errorf("expected DockerDir '/docker', got %q", cfg.DockerDir)
	}
	mcfg := cfg.DatasetConfig.ModuleConfig
	if mcfg.Limit != 10 {
		t.Errorf("expected Limit 10, got %d", mcfg.Limit)
	}
	if mcfg.FilterArchived {
		t.Errorf("expected FilterArchived false, got %v", mcfg.FilterArchived)
	}
	if mcfg.FilterEducational {
		t.Errorf("expected FilterEducational false, got %v", mcfg.FilterEducational)
	}
	if mcfg.FilterOutOfDate {
		t.Errorf("expected FilterOutOfDate false, got %v", mcfg.FilterOutOfDate)
	}
	if mcfg.FilterIncomplete {
		t.Errorf("expected FilterIncomplete false, got %v", mcfg.FilterIncomplete)
	}
}
