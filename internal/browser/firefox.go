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
	marker       = "// [traffic-agent] managed — do not edit this line"
	quicPref     = `user_pref("network.http.http3.enabled", false);`
	blockStart   = marker + " BEGIN"
	blockEnd     = marker + " END"
	blockContent = blockStart + "\n" + quicPref + "\n" + blockEnd
)

// ConfigureFirefox discovers all Firefox profiles for the real (non-root)
// user and disables QUIC by writing a user.js preference block.
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

	profilesDir := filepath.Join(homeDir, ".mozilla", "firefox")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", profilesDir, err)
	}

	configured := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		profileDir := filepath.Join(profilesDir, e.Name())

		// Only configure profiles that have been used (prefs.js exists).
		if _, err := os.Stat(filepath.Join(profileDir, "prefs.js")); err != nil {
			continue
		}

		if err := writeQUICDisable(profileDir, uid, gid); err != nil {
			log.Printf("[browser] profile %s: %v", e.Name(), err)
			continue
		}
		configured++
		log.Printf("[browser] Firefox profile %s: QUIC disabled via user.js", e.Name())
	}

	// Warn if Firefox is currently running — change takes effect on next launch.
	if isFirefoxRunning() {
		log.Println("[browser] WARNING: Firefox is currently running — QUIC disable takes effect after restart")
	}

	return configured, nil
}

// RestoreFirefox removes the traffic-agent QUIC-disable block from all
// Firefox profiles found in the real user's home directory.
func RestoreFirefox() {
	homeDir, _, _, err := resolveRealUser()
	if err != nil {
		return
	}

	profilesDir := filepath.Join(homeDir, ".mozilla", "firefox")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		profileDir := filepath.Join(profilesDir, e.Name())
		removed, err := removeQUICDisable(profileDir)
		if err != nil {
			log.Printf("[browser] restore profile %s: %v", e.Name(), err)
		} else if removed {
			log.Printf("[browser] Firefox profile %s: QUIC restored", e.Name())
		}
	}
}

// writeQUICDisable appends (or confirms) the QUIC-disable block in user.js.
func writeQUICDisable(profileDir string, uid, gid int) error {
	userJsPath := filepath.Join(profileDir, "user.js")

	// If already configured, skip.
	if data, err := os.ReadFile(userJsPath); err == nil {
		if strings.Contains(string(data), blockStart) {
			return nil
		}
	}

	f, err := os.OpenFile(userJsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open user.js: %w", err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "\n%s\n", blockContent); err != nil {
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
