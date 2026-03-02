package browser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProfilesINI_SnapFirefox(t *testing.T) {
	// Simulates snap Firefox profiles.ini with a single default profile.
	dir := t.TempDir()
	iniContent := `[Profile0]
Name=default
IsRelative=1
Path=j78hwgjq.default
Default=1

[General]
StartWithLastProfile=1
Version=2
`
	os.WriteFile(filepath.Join(dir, "profiles.ini"), []byte(iniContent), 0644)
	os.MkdirAll(filepath.Join(dir, "j78hwgjq.default"), 0755)

	profiles := parseProfilesINI(filepath.Join(dir, "profiles.ini"), dir)
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d: %v", len(profiles), profiles)
	}
	if filepath.Base(profiles[0]) != "j78hwgjq.default" {
		t.Errorf("expected j78hwgjq.default, got %s", filepath.Base(profiles[0]))
	}
}

func TestParseProfilesINI_MultipleProfiles(t *testing.T) {
	// Simulates regular Firefox profiles.ini with multiple profiles + install sections.
	dir := t.TempDir()
	iniContent := `[Install85D800AE2EF5E25F]
Default=kd44z2ir.default-release-1
Locked=1

[InstallD0D867BF6BB1F30]
Default=d2m4biiw.default-release
Locked=1

[Profile1]
Name=default
IsRelative=1
Path=g140y8t0.default
Default=1

[Profile0]
Name=default-release
IsRelative=1
Path=d2m4biiw.default-release

[General]
StartWithLastProfile=1
Version=2

[Profile2]
Name=default-release-1
IsRelative=1
Path=kd44z2ir.default-release-1
`
	os.WriteFile(filepath.Join(dir, "profiles.ini"), []byte(iniContent), 0644)
	// Create all three profile dirs.
	os.MkdirAll(filepath.Join(dir, "g140y8t0.default"), 0755)
	os.MkdirAll(filepath.Join(dir, "d2m4biiw.default-release"), 0755)
	os.MkdirAll(filepath.Join(dir, "kd44z2ir.default-release-1"), 0755)

	profiles := parseProfilesINI(filepath.Join(dir, "profiles.ini"), dir)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d: %v", len(profiles), profiles)
	}

	names := make(map[string]bool)
	for _, p := range profiles {
		names[filepath.Base(p)] = true
	}
	for _, expected := range []string{"g140y8t0.default", "d2m4biiw.default-release", "kd44z2ir.default-release-1"} {
		if !names[expected] {
			t.Errorf("missing profile %s in %v", expected, profiles)
		}
	}
}

func TestParseProfilesINI_SkipsNonExistentDirs(t *testing.T) {
	dir := t.TempDir()
	iniContent := `[Profile0]
Name=default
IsRelative=1
Path=exists.default

[Profile1]
Name=other
IsRelative=1
Path=missing.default
`
	os.WriteFile(filepath.Join(dir, "profiles.ini"), []byte(iniContent), 0644)
	os.MkdirAll(filepath.Join(dir, "exists.default"), 0755)
	// Do NOT create missing.default.

	profiles := parseProfilesINI(filepath.Join(dir, "profiles.ini"), dir)
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d: %v", len(profiles), profiles)
	}
	if filepath.Base(profiles[0]) != "exists.default" {
		t.Errorf("expected exists.default, got %s", filepath.Base(profiles[0]))
	}
}

func TestParseProfilesINI_AbsolutePath(t *testing.T) {
	dir := t.TempDir()
	absProfileDir := filepath.Join(dir, "abs-profile")
	os.MkdirAll(absProfileDir, 0755)

	iniContent := `[Profile0]
Name=absolute
IsRelative=0
Path=` + absProfileDir + `
`
	os.WriteFile(filepath.Join(dir, "profiles.ini"), []byte(iniContent), 0644)

	profiles := parseProfilesINI(filepath.Join(dir, "profiles.ini"), dir)
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d: %v", len(profiles), profiles)
	}
	if profiles[0] != absProfileDir {
		t.Errorf("expected %s, got %s", absProfileDir, profiles[0])
	}
}

func TestParseProfilesINI_MissingFile(t *testing.T) {
	profiles := parseProfilesINI("/nonexistent/profiles.ini", "/nonexistent")
	if len(profiles) != 0 {
		t.Fatalf("expected 0 profiles for missing file, got %d", len(profiles))
	}
}

func TestDiscoverFirefoxProfiles_BothLocations(t *testing.T) {
	// Simulate a home directory with both regular and snap Firefox.
	homeDir := t.TempDir()

	// Regular Firefox: ~/.mozilla/firefox/
	regularDir := filepath.Join(homeDir, ".mozilla", "firefox")
	os.MkdirAll(regularDir, 0755)
	os.MkdirAll(filepath.Join(regularDir, "abc.default-release"), 0755)
	os.WriteFile(filepath.Join(regularDir, "profiles.ini"), []byte(`[Profile0]
Name=default-release
IsRelative=1
Path=abc.default-release
`), 0644)

	// Snap Firefox: ~/snap/firefox/common/.mozilla/firefox/
	snapDir := filepath.Join(homeDir, "snap", "firefox", "common", ".mozilla", "firefox")
	os.MkdirAll(snapDir, 0755)
	os.MkdirAll(filepath.Join(snapDir, "xyz.default"), 0755)
	os.WriteFile(filepath.Join(snapDir, "profiles.ini"), []byte(`[Profile0]
Name=default
IsRelative=1
Path=xyz.default
`), 0644)

	profiles := discoverFirefoxProfiles(homeDir)
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d: %v", len(profiles), profiles)
	}

	names := make(map[string]bool)
	for _, p := range profiles {
		names[filepath.Base(p)] = true
	}
	if !names["abc.default-release"] {
		t.Errorf("missing regular profile abc.default-release")
	}
	if !names["xyz.default"] {
		t.Errorf("missing snap profile xyz.default")
	}
}
