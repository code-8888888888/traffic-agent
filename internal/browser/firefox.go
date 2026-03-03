// Package browser provides auto-configuration helpers for browsers to
// enable reliable traffic interception.
//
// Firefox QUIC management:
//
// Firefox (148+) enables HTTP/3 (QUIC) by default. QUIC traffic cannot be
// intercepted by NSS uprobes because NSS stores AEAD encryption keys as
// opaque PKCS#11 handles — the raw key bytes never appear in memory.
//
// To capture all HTTPS traffic, we disable QUIC in Firefox so it falls back
// to HTTP/2 over TLS. HTTP/2 is functionally equivalent for all websites;
// QUIC is a transport-layer performance optimization, not a feature.
//
// The agent writes a user.js entry into each Firefox profile on startup and
// removes it on shutdown, making the change transparent to the user.
package browser

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	marker     = "// [traffic-agent] managed — do not edit this line"
	blockStart = marker + " BEGIN"
	blockEnd   = marker + " END"

	// Fully disable HTTP/3 (QUIC) in Firefox.
	//
	// network.http.http3.enabled=false is the primary switch, but Firefox 148+
	// still upgrades to H3 when the server advertises it via Alt-Svc headers
	// (e.g., `h3=":443"; ma=86400`). To prevent this, we also disable Alt-Svc
	// entirely and clear the Alt-Svc mapping cache.
	blockContent = blockStart + "\n" +
		`user_pref("network.http.http3.enabled", false);` + "\n" +
		`user_pref("network.http.altsvc.enabled", false);` + "\n" +
		`user_pref("network.http.altsvc.oe", false);` + "\n" +
		blockEnd
)

// ConfigureFirefox discovers all Firefox profiles for the real (non-root)
// user and disables QUIC by writing a user.js preference block.
//
// Profiles are discovered by parsing profiles.ini (not by scanning
// directories), ensuring only active profiles are configured. Both
// regular (~/.mozilla/firefox/) and snap (~/snap/firefox/common/.mozilla/
// firefox/) locations are checked.
//
// When the agent runs via sudo, SUDO_USER is used to find the correct
// home directory and file ownership is preserved.
//
// Returns the number of profiles configured and any error.
func ConfigureFirefox() (int, error) {
	homeDir, uid, gid, err := resolveRealUser()
	if err != nil {
		return 0, fmt.Errorf("resolve user home: %w", err)
	}

	profileDirs := discoverFirefoxProfiles(homeDir)
	if len(profileDirs) == 0 {
		return 0, fmt.Errorf("no Firefox profiles found in profiles.ini")
	}

	configured := 0
	for _, profileDir := range profileDirs {
		if err := writeQUICDisable(profileDir, uid, gid); err != nil {
			log.Printf("[browser] profile %s: %v", filepath.Base(profileDir), err)
			continue
		}
		configured++
		log.Printf("[browser] Firefox profile %s: QUIC disabled via user.js", filepath.Base(profileDir))
	}

	// Warn if Firefox is currently running — change takes effect on next launch.
	if isFirefoxRunning() {
		log.Println("[browser] WARNING: Firefox is currently running — QUIC disable takes effect after restart")
	}

	return configured, nil
}

// RestoreFirefox removes the traffic-agent QUIC-disable block from all
// Firefox profiles found in the real user's home directory.
//
// For restore, we scan both profiles.ini AND all directories (to clean up
// any stale user.js entries from before the profiles.ini fix).
func RestoreFirefox() {
	homeDir, _, _, err := resolveRealUser()
	if err != nil {
		return
	}

	// Collect profile dirs from profiles.ini + directory scan (union).
	seen := make(map[string]bool)
	var profileDirs []string

	for _, dir := range discoverFirefoxProfiles(homeDir) {
		if !seen[dir] {
			seen[dir] = true
			profileDirs = append(profileDirs, dir)
		}
	}

	// Also scan directories to clean up any stale user.js from before the fix.
	for _, rootDir := range firefoxRootDirs(homeDir) {
		entries, err := os.ReadDir(rootDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(rootDir, e.Name())
			if !seen[dir] {
				seen[dir] = true
				profileDirs = append(profileDirs, dir)
			}
		}
	}

	for _, profileDir := range profileDirs {
		removed, err := removeQUICDisable(profileDir)
		if err != nil {
			log.Printf("[browser] restore profile %s: %v", filepath.Base(profileDir), err)
		} else if removed {
			log.Printf("[browser] Firefox profile %s: QUIC restored", filepath.Base(profileDir))
		}
	}
}

// firefoxRootDirs returns the Firefox profile root directories to check.
// Regular Firefox uses ~/.mozilla/firefox/, snap Firefox uses
// ~/snap/firefox/common/.mozilla/firefox/.
func firefoxRootDirs(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".mozilla", "firefox"),
		filepath.Join(homeDir, "snap", "firefox", "common", ".mozilla", "firefox"),
	}
}

// discoverFirefoxProfiles parses profiles.ini in all known Firefox root
// directories and returns the absolute paths of all listed profile dirs.
func discoverFirefoxProfiles(homeDir string) []string {
	seen := make(map[string]bool)
	var dirs []string

	for _, rootDir := range firefoxRootDirs(homeDir) {
		iniPath := filepath.Join(rootDir, "profiles.ini")
		profiles := parseProfilesINI(iniPath, rootDir)
		for _, p := range profiles {
			if !seen[p] {
				seen[p] = true
				dirs = append(dirs, p)
			}
		}
	}
	return dirs
}

// parseProfilesINI reads a Firefox profiles.ini file and returns the
// absolute paths of all [ProfileN] entries that point to existing directories.
//
// The INI format contains sections like:
//
//	[Profile0]
//	Name=default
//	IsRelative=1
//	Path=abc123.default
//	Default=1
//
// IsRelative=1 means Path is relative to the directory containing profiles.ini.
// IsRelative=0 means Path is an absolute filesystem path.
func parseProfilesINI(iniPath, rootDir string) []string {
	f, err := os.Open(iniPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var profiles []string
	var inProfile bool
	var path string
	isRelative := true

	flush := func() {
		if !inProfile || path == "" {
			inProfile = false
			path = ""
			isRelative = true
			return
		}
		var absPath string
		if isRelative {
			absPath = filepath.Join(rootDir, path)
		} else {
			absPath = path
		}
		// Only include profiles whose directory actually exists.
		if info, err := os.Stat(absPath); err == nil && info.IsDir() {
			profiles = append(profiles, absPath)
		}
		inProfile = false
		path = ""
		isRelative = true
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// New section header.
		if strings.HasPrefix(line, "[") {
			flush()
			// Only process [ProfileN] sections.
			inProfile = strings.HasPrefix(line, "[Profile")
			continue
		}

		if !inProfile {
			continue
		}

		if strings.HasPrefix(line, "Path=") {
			path = strings.TrimPrefix(line, "Path=")
		} else if strings.HasPrefix(line, "IsRelative=") {
			isRelative = strings.TrimPrefix(line, "IsRelative=") == "1"
		}
	}
	flush() // handle last section

	return profiles
}

// writeQUICDisable writes the QUIC-disable block in user.js.
// If a previous version of the block exists, it is replaced with the current content.
func writeQUICDisable(profileDir string, uid, gid int) error {
	userJsPath := filepath.Join(profileDir, "user.js")

	data, readErr := os.ReadFile(userJsPath)
	content := ""
	if readErr == nil {
		content = string(data)
	}

	// If the current block is already present verbatim, skip.
	if strings.Contains(content, blockContent) {
		return nil
	}

	// If an older version of the block exists, remove it first.
	if strings.Contains(content, blockStart) {
		lines := strings.Split(content, "\n")
		var filtered []string
		inBlock := false
		for _, line := range lines {
			if line == blockStart {
				inBlock = true
				continue
			}
			if line == blockEnd {
				inBlock = false
				continue
			}
			if !inBlock {
				filtered = append(filtered, line)
			}
		}
		content = strings.Join(filtered, "\n")
	}

	// Append the current block.
	content = strings.TrimRight(content, "\n")
	if content != "" {
		content += "\n"
	}
	content += "\n" + blockContent + "\n"

	if err := os.WriteFile(userJsPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write user.js: %w", err)
	}

	// Preserve ownership when running as root via sudo.
	if uid >= 0 && gid >= 0 {
		_ = os.Chown(userJsPath, uid, gid)
	}

	return nil
}

// removeQUICDisable strips the traffic-agent managed block from user.js.
// Returns true if the block was found and removed.
func removeQUICDisable(profileDir string) (bool, error) {
	userJsPath := filepath.Join(profileDir, "user.js")
	data, err := os.ReadFile(userJsPath)
	if err != nil {
		return false, nil // no user.js — nothing to restore
	}

	content := string(data)
	if !strings.Contains(content, blockStart) {
		return false, nil // our block not present
	}

	// Remove the block between BEGIN and END markers (inclusive).
	lines := strings.Split(content, "\n")
	var filtered []string
	inBlock := false
	for _, line := range lines {
		if line == blockStart {
			inBlock = true
			continue
		}
		if line == blockEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			filtered = append(filtered, line)
		}
	}

	result := strings.Join(filtered, "\n")
	// Clean up excess trailing newlines left by removal.
	result = strings.TrimRight(result, "\n")
	if result != "" {
		result += "\n"
	}

	return true, os.WriteFile(userJsPath, []byte(result), 0644)
}

// resolveRealUser returns the home directory and uid/gid of the real user.
// When running via sudo, it uses SUDO_USER; otherwise the current user.
func resolveRealUser() (homeDir string, uid, gid int, err error) {
	uid, gid = -1, -1

	// Check for sudo — the agent typically runs as root.
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && sudoUser != "root" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			uid, _ = strconv.Atoi(u.Uid)
			gid, _ = strconv.Atoi(u.Gid)
			return u.HomeDir, uid, gid, nil
		}
	}

	// Fallback: try HOME env var, then current user.
	if h := os.Getenv("HOME"); h != "" && h != "/root" {
		return h, uid, gid, nil
	}

	// Try SUDO_HOME or resolve from /etc/passwd.
	if sudoUser != "" {
		return "/home/" + sudoUser, uid, gid, nil
	}

	// Last resort: scan /home for any user with Firefox profiles.
	entries, err := os.ReadDir("/home")
	if err != nil {
		return "", -1, -1, fmt.Errorf("cannot determine user home directory")
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		candidate := filepath.Join("/home", e.Name(), ".mozilla", "firefox")
		if _, err := os.Stat(candidate); err == nil {
			u, err := user.Lookup(e.Name())
			if err == nil {
				uid, _ = strconv.Atoi(u.Uid)
				gid, _ = strconv.Atoi(u.Gid)
			}
			return filepath.Join("/home", e.Name()), uid, gid, nil
		}
	}

	return "", -1, -1, fmt.Errorf("no user with Firefox profiles found")
}

// isFirefoxRunning checks if any Firefox process is currently running.
func isFirefoxRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if name == "firefox" || name == "firefox-bin" || name == "Web Content" || name == "GeckoMain" {
			return true
		}
	}
	return false
}

// IsFirefoxInstalled returns true if Firefox appears to be installed.
func IsFirefoxInstalled() bool {
	// Check common paths.
	for _, p := range []string{
		"/usr/bin/firefox",
		"/snap/bin/firefox",
		"/usr/lib/firefox/firefox",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// WaitForFirefoxAndConfigure can be called in a goroutine to periodically
// check for new Firefox profiles (e.g., if Firefox is installed but no profile
// exists yet because it hasn't been launched).
func WaitForFirefoxAndConfigure(stop <-chan struct{}) {
	// Not implemented yet — the startup configuration handles existing profiles.
	// Future: watch for new profile creation and configure on-the-fly.
	_ = stop
}

// ConfigureChromiumQUIC is a stub for future Chromium QUIC configuration.
// Chromium uses --disable-quic command-line flag or enterprise policy.
// Currently not implemented because Chromium's stripped BoringSSL prevents
// TLS interception regardless of QUIC status.
func ConfigureChromiumQUIC() error {
	return fmt.Errorf("chromium TLS interception not supported (stripped BoringSSL)")
}

// platformChown sets file ownership. No-op if uid/gid are -1.
func platformChown(path string, uid, gid int) {
	if uid >= 0 && gid >= 0 {
		_ = syscall.Chown(path, uid, gid)
	}
}
