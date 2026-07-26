package main

import (
	"slices"
	"testing"
)

// pkgnames and files reused across the cases below
const (
	pkgNix    = "nix"
	fileNix   = "nix-2.35.1-2.1-x86_64.pkg.tar.zst"
	fileOther = "other-1.0-1.1-x86_64.pkg.tar.zst"
)

func diskState(files ...string) (diskFiles map[string]struct{}, diskByName map[string]string) {
	diskFiles = make(map[string]struct{}, len(files))
	diskByName = make(map[string]string, len(files))
	for _, f := range files {
		diskFiles[f] = struct{}{}
		diskByName[Package(f).Name()] = f
	}
	return diskFiles, diskByName
}

func TestDiffRepoDB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		listed     map[string]string
		files      []string
		wantReadd  []string
		wantRemove []string
		// wantOrphans are the removals repoDBHK may re-check against the
		// directory. A removal paired with a re-add must never appear here:
		// re-checking it would strip the pairing and re-break the repair.
		wantOrphans []string
	}{
		{
			name:   "db agrees with disk",
			listed: map[string]string{pkgNix: fileNix},
			files:  []string{fileNix},
		},
		{
			// the real extra-x86-64-v2 case: db advertises a deleted file while
			// a newer one sits on disk. Both directions must fire, because
			// repo-add -n/-p would otherwise skip the stale entry.
			name:       "db lists deleted file, newer one on disk",
			listed:     map[string]string{"heaptrack": "heaptrack-1.5.0-9.1-x86_64.pkg.tar.zst"},
			files:      []string{"heaptrack-1.5.0-10.1-x86_64.pkg.tar.zst"},
			wantReadd:  []string{"heaptrack-1.5.0-10.1-x86_64.pkg.tar.zst"},
			wantRemove: []string{"heaptrack"},
		},
		{
			// the real multilib-x86-64-v2 case: package invisible to clients
			name:      "on disk but absent from db",
			listed:    map[string]string{"other": fileOther},
			files:     []string{fileOther, "cmucl-21e-1.2-x86_64.pkg.tar.zst"},
			wantReadd: []string{"cmucl-21e-1.2-x86_64.pkg.tar.zst"},
		},
		{
			name:        "db entry with no package at all",
			listed:      map[string]string{"gone": "gone-1.0-1.1-x86_64.pkg.tar.zst"},
			files:       []string{fileOther},
			wantReadd:   []string{fileOther},
			wantRemove:  []string{"gone"},
			wantOrphans: []string{"gone"},
		},
		{
			// a partially applied repo-add leaves the old file in place, so the
			// filename still resolves and only the version reveals the drift
			name:       "db lists older version whose file still exists",
			listed:     map[string]string{pkgNix: fileNix},
			files:      []string{fileNix, "nix-2.35.1-2.2-x86_64.pkg.tar.zst"},
			wantReadd:  []string{"nix-2.35.1-2.2-x86_64.pkg.tar.zst"},
			wantRemove: []string{pkgNix},
		},
		{
			// epoch in the version must not confuse name/version parsing
			name:   "epoch version agrees",
			listed: map[string]string{"ldc": "ldc-3:1.42.0-1.1-x86_64.pkg.tar.zst"},
			files:  []string{"ldc-3:1.42.0-1.1-x86_64.pkg.tar.zst"},
		},
		{
			// repo-add -p refuses the downgrade, so the removal has to be paired
			// or the file is silently ignored and the entry stays broken
			name:        "db lists a newer version whose file is gone",
			listed:      map[string]string{pkgNix: "nix-2.35.1-3.1-x86_64.pkg.tar.zst"},
			files:       []string{fileNix},
			wantReadd:   []string{fileNix},
			wantRemove:  []string{pkgNix},
			wantOrphans: nil,
		},
		{
			// arch-any moved to a concrete arch: same version, different
			// filename, which repo-add -n skips unless the entry is dropped
			name:        "same version under a different filename",
			listed:      map[string]string{"foo": "foo-1.0-1.1-any.pkg.tar.zst"},
			files:       []string{"foo-1.0-1.1-x86_64.pkg.tar.zst"},
			wantReadd:   []string{"foo-1.0-1.1-x86_64.pkg.tar.zst"},
			wantRemove:  []string{"foo"},
			wantOrphans: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			diskFiles, diskByName := diskState(tt.files...)
			fix, orphans := diffRepoDB("extra-x86-64-v3", tt.listed, diskFiles, diskByName)

			sorted := func(in []string) []string {
				out := slices.Clone(in)
				slices.Sort(out)
				return out
			}

			if got, want := sorted(fix.readd), sorted(tt.wantReadd); !slices.Equal(got, want) {
				t.Errorf("readd = %v, want %v", got, want)
			}
			if got, want := sorted(fix.remove), sorted(tt.wantRemove); !slices.Equal(got, want) {
				t.Errorf("remove = %v, want %v", got, want)
			}
			if got, want := sorted(orphans), sorted(tt.wantOrphans); !slices.Equal(got, want) {
				t.Errorf("orphans = %v, want %v", got, want)
			}
			// a paired removal must not be re-checked, or the pairing is lost
			for _, name := range orphans {
				if _, onDisk := diskByName[name]; onDisk {
					t.Errorf("%s reported as orphan while a file for it exists", name)
				}
			}
		})
	}
}
