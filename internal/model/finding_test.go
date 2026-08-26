package model

import "testing"

func TestNetworkToolsReportALiveTargetSource(t *testing.T) {
	// The report groups by source; before this, every network finding fell through
	// to source-code, so a TLS or header problem read as a code problem.
	for _, tool := range []string{"surface", "testssl", "nuclei", "zap", "ffuf", "llm-recon"} {
		if got := InferSource(tool, "", "https://example.com"); got != SourceNetwork {
			t.Errorf("%s source = %q, want %q", tool, got, SourceNetwork)
		}
	}
	// The filesystem tools are unchanged.
	if InferSource("semgrep", "", "app/main.go") != SourceCode {
		t.Error("semgrep should still be source-code")
	}
	if InferSource("trivy", "vuln", "go.mod") != SourceDependency {
		t.Error("trivy vuln should still be a dependency finding")
	}
}
