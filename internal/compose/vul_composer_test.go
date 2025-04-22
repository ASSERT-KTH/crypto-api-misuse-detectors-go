package compose

import (
   "os"
   "path/filepath"
   "strings"
   "testing"

   "github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// Test that VulComposer.ComposeStr includes the expected service block, args, and writes metadata
func TestVulComposerComposeStr(t *testing.T) {
   // Prepare a single vulnerability with one package
   pkg := dataset.VulPackage{
       Name:              "pkg1",
       VulnerableGitTags: []string{"v1.0.0"},
       GitTag:            "v1.0.0",
       GoVersion:         "1.17",
       Publish:           "2020-01-01",
       VulName:           "VulnName",
       VulRange:          ">=1.0.0",
       Level:             "high",
       Score:             "9.8",
       Remediation:       "fix it",
       Summary:           "desc",
   }
   vul := dataset.Vulnerability{
       ID:          42,
       Repo:        dataset.Repository{RepoSlug: "github.com/foo/bar", URL: "https://github.com/foo/bar"},
       References:  []string{"ref1", "ref2"},
       CWE:         "CWE-123",
       CVE:         "CVE-2020-0001",
       VulPackages: []dataset.VulPackage{pkg},
   }
   ds := &dataset.VulnerabilityDataset{Vulnerabilities: []dataset.Vulnerability{vul}}
   // Use TempDir to allow metadata file creation
   outdir := t.TempDir()
   composer := NewVulComposer(ds, outdir, 4)
   yaml := composer.ComposeStr()
   // Expected service name for one vulnerability
   expectedService := "foo-bar-42-1"
   if !strings.Contains(yaml, expectedService+":") {
       t.Errorf("ComposeStr missing service name %s", expectedService)
   }
   // Check that build args include REPO_URL, GIT_TAG, GO_VERSION
   if !strings.Contains(yaml, `REPO_URL: "https://github.com/foo/bar"`) {
       t.Errorf("ComposeStr missing REPO_URL argument")
   }
   if !strings.Contains(yaml, `GIT_TAG: "v1.0.0"`) {
       t.Errorf("ComposeStr missing GIT_TAG argument")
   }
   if !strings.Contains(yaml, `GO_VERSION: "1.17"`) {
       t.Errorf("ComposeStr missing GO_VERSION argument")
   }
   // Check that metadata file was created
   metadataPath := filepath.Join(outdir, expectedService, "vulnerability_info.json")
   if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
       t.Errorf("expected metadata file %s to exist", metadataPath)
   }
}