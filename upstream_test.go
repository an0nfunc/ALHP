package main

import (
	"slices"
	"testing"
)

// TestGitCommandIdentifiesALHP pins what every git call to gitlab.archlinux.org
// carries: the User-Agent, no credential prompt to hang on, and a cancel that
// reaches git-remote-https rather than only git itself.
func TestGitCommandIdentifiesALHP(t *testing.T) {
	t.Parallel()

	cmd := gitCommand(t.Context(), "/nonexistent", "status")
	for _, want := range []string{"GIT_HTTP_USER_AGENT=" + upstreamUserAgent, "GIT_TERMINAL_PROMPT=0"} {
		if !slices.Contains(cmd.Env, want) {
			t.Errorf("git environment lacks %q", want)
		}
	}
	if cmd.Dir != "/nonexistent" {
		t.Errorf("Dir = %q, want /nonexistent", cmd.Dir)
	}
	if cmd.SysProcAttr == nil || !cmd.SysProcAttr.Setpgid || cmd.Cancel == nil || cmd.WaitDelay == 0 {
		t.Error("git does not run in its own process group with a group kill on cancel and a WaitDelay")
	}
}
