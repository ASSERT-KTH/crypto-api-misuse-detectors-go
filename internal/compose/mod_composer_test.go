package compose

import (
   "strings"
   "testing"

   "github.com/ASSERT-KTH/go-cryptoapi/internal/dataset"
)

// Test that ModComposer.ComposeStr includes the expected service block and args
func TestModComposerComposeStr(t *testing.T) {
   ds := &dataset.ModuleDataset{Modules: []dataset.Module{{
       RepoName:   "github.com/foo/bar",
       URL:        "https://github.com/foo/bar",
       ReleaseTag: "v1.2.3",
       GoVersion:  "1.15",
   }}}
   composer := NewModComposer(ds, "outdir", 4)
   yaml := composer.ComposeStr()
   // Header
   if !strings.HasPrefix(yaml, "version: '3.8'") {
       t.Errorf("ComposeStr missing header, got: %s", yaml)
   }
   // Expected service name for one module
   expectedService := "foo-bar-mod0-pkg1"
   if !strings.Contains(yaml, expectedService+":") {
       t.Errorf("ComposeStr missing service name %s", expectedService)
   }
   // Check that build args include REPO_URL, GIT_TAG, GO_VERSION
   if !strings.Contains(yaml, `REPO_URL: "https://github.com/foo/bar"`) {
       t.Errorf("ComposeStr missing REPO_URL argument")
   }
   if !strings.Contains(yaml, `GIT_TAG: "v1.2.3"`) {
       t.Errorf("ComposeStr missing GIT_TAG argument")
   }
   if !strings.Contains(yaml, `GO_VERSION: "1.15"`) {
       t.Errorf("ComposeStr missing GO_VERSION argument")
   }
}