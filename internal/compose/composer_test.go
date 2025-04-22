package compose

import (
   "fmt"
   "os"
   "path/filepath"
   "strings"
   "testing"

   "github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

func TestGenerateComposeHeader(t *testing.T) {
   want := "version: '3.8'\n\nservices:\n"
   if got := generateComposeHeader(); got != want {
       t.Errorf("generateComposeHeader() = %q; want %q", got, want)
   }
}

func TestGenerateVolumeConfig(t *testing.T) {
   got := generateVolumeConfig()
   if !strings.Contains(got, "volumes:") {
       t.Error("generateVolumeConfig missing 'volumes:'")
   }
   if !strings.Contains(got, "driver: local") {
       t.Error("generateVolumeConfig missing 'driver: local'")
   }
   if !strings.Contains(got, "device: ${BASE_DIR}/gopher") {
       t.Error("generateVolumeConfig missing expected device path")
   }
}

func TestGenerateServiceName(t *testing.T) {
   cases := []struct{ repo, id, want string }{
       {"github.com/user/repo", "123", "user-repo-123"},
       {"user/repo", "id", "user-repo-id"},
       {"example", "ID", "example-id"},
   }
   for _, c := range cases {
       if got := generateServiceName(c.repo, c.id); got != c.want {
           t.Errorf("generateServiceName(%q, %q) = %q; want %q", c.repo, c.id, got, c.want)
       }
   }
}

func TestGenerateServiceStr(t *testing.T) {
   repo := "https://example.com/foo"
   gitTag := "v1.0.0"
   goVer := "1.15"
   svcName := "service-name"
   analysisDir := "analysis/dir"
   out := generateServiceStr(repo, gitTag, goVer, svcName, analysisDir)
   tests := []string{
       fmt.Sprintf("  %s:\n", svcName),
       "build:",
       "context: .",
       fmt.Sprintf("REPO_URL: \"%s\"", repo),
       fmt.Sprintf("GIT_TAG: \"%s\"", gitTag),
       fmt.Sprintf("GO_VERSION: \"%s\"", goVer),
       fmt.Sprintf("container_name: %s", svcName),
       "gopher-shared:/analysis/gopher",
       fmt.Sprintf("${BASE_DIR}/%s:/analysis/repo/scan_results", analysisDir),
   }
   for _, sub := range tests {
       if !strings.Contains(out, sub) {
           t.Errorf("generateServiceStr missing %q", sub)
       }
   }
}

func TestWriteComposeFile(t *testing.T) {
   dir := t.TempDir()
   content := "hello compose"
   path, err := WriteComposeFile(dir, content)
   if err != nil {
       t.Fatalf("WriteComposeFile error: %v", err)
   }
   data, err := os.ReadFile(path)
   if err != nil {
       t.Fatalf("failed to read file: %v", err)
   }
   if string(data) != content {
       t.Errorf("file content = %q; want %q", string(data), content)
   }
   if filepath.Base(path) != "compose.yaml" {
       t.Errorf("file name = %q; want %q", filepath.Base(path), "compose.yaml")
   }
}

func TestNewComposer(t *testing.T) {
   // ModuleDataset
   modDS := &dataset.ModuleDataset{Modules: []dataset.Module{}}
   cMod := NewComposer(modDS, "outdir", 2)
   mc, ok := cMod.(*ModComposer)
   if !ok {
       t.Fatalf("NewComposer(ModuleDataset) returned %T; want *ModComposer", cMod)
   }
   if mc.OutDir != "outdir" {
       t.Errorf("ModComposer.Config.OutDir = %q; want %q", mc.OutDir, "outdir")
   }
   if mc.Parallelism != 2 {
       t.Errorf("ModComposer.Config.Parallelism = %d; want %d", mc.Parallelism, 2)
   }
   // VulnerabilityDataset
   vulDS := &dataset.VulnerabilityDataset{Vulnerabilities: []dataset.Vulnerability{}}
   cVul := NewComposer(vulDS, "dir2", 3)
   vc, ok := cVul.(*VulComposer)
   if !ok {
       t.Fatalf("NewComposer(VulnerabilityDataset) returned %T; want *VulComposer", cVul)
   }
   if vc.OutDir != "dir2" {
       t.Errorf("VulComposer.Config.OutDir = %q; want %q", vc.OutDir, "dir2")
   }
   if vc.Parallelism != 3 {
       t.Errorf("VulComposer.Config.Parallelism = %d; want %d", vc.Parallelism, 3)
   }
   // Default parallelism when <= 0
   cDef := NewComposer(modDS, "", 0)
   mc2 := cDef.(*ModComposer)
   if mc2.Parallelism != 4 {
       t.Errorf("Default Parallelism = %d; want %d", mc2.Parallelism, 4)
   }
}

// fakeDS implements dataset.Dataset but is not a ModuleDataset or VulnerabilityDataset
type fakeDS struct{}
func (f *fakeDS) Count() int                    { return 0 }
func (f *fakeDS) Type() dataset.DatasetType     { return "" }
func (f *fakeDS) String() string                { return "" }
func (f *fakeDS) ID() string                    { return "" }

func TestNewComposerUnsupported(t *testing.T) {
   defer func() {
       if r := recover(); r == nil {
           t.Errorf("NewComposer did not panic for unsupported dataset")
       }
   }()
   _ = NewComposer(&fakeDS{}, "x", 1)
}