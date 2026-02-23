// Package config loads and validates the traffic-agent YAML configuration.
package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultConfigPath = "/etc/traffic-agent/config.yaml"

// Config is the root configuration structure.
type Config struct {
	// Interface is the network interface to attach TC hooks to (e.g. "eth0").
	Interface string `yaml:"interface"`

	// Ports lists the TCP ports to capture. Defaults to [80, 443, 8080, 8443].
	Ports []int `yaml:"ports"`

	Filter      FilterConfig `yaml:"filter"`
	Output      OutputConfig `yaml:"output"`
	TLS         TLSConfig    `yaml:"tls"`
	EventStream StreamConfig `yaml:"event_stream"`
}

// FilterConfig defines traffic filtering rules. Empty/zero values mean "match all".
type FilterConfig struct {
	// SrcIPs limits capture to packets from these source IP addresses.
	SrcIPs []string `yaml:"src_ips"`
	// DstIPs limits capture to packets destined for these IP addresses.
	DstIPs []string `yaml:"dst_ips"`
	// SrcPorts limits capture to packets from these source ports.
	SrcPorts []int `yaml:"src_ports"`
	// DstPorts limits capture to packets destined for these ports.
	DstPorts []int `yaml:"dst_ports"`
	// PIDs limits capture to traffic from these process IDs.
	PIDs []int `yaml:"pids"`
	// Processes limits capture to traffic from processes matching these names.
	Processes []string `yaml:"processes"`
}

// OutputConfig configures the structured JSON log output.
type OutputConfig struct {
	// Stdout enables logging to standard output.
	Stdout bool `yaml:"stdout"`
	// File is the path of the output log file. Empty disables file logging.
	File string `yaml:"file"`
	// MaxSizeMB is the maximum size in megabytes before the log file is rotated.
	MaxSizeMB int `yaml:"max_size_mb"`
	// MaxAgeDays is the maximum number of days to retain old log files.
	MaxAgeDays int `yaml:"max_age_days"`
	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `yaml:"max_backups"`
	// Compress enables gzip compression of rotated log files.
	Compress bool `yaml:"compress"`
}

// BoringSSlExecutable describes a single executable or shared library that
// contains a statically or dynamically linked BoringSSL and should have
// SSL_write/SSL_read uprobes attached to it.
//
// Use this for applications (e.g. Chromium) that bundle BoringSSL internally
// rather than linking against the system libssl.so.
type BoringSSlExecutable struct {
	// Path is the absolute path to the executable or shared library.
	// For snap packages you may use the "current" symlink
	// (e.g. /snap/chromium/current/usr/lib/chromium-browser/chrome);
	// the agent resolves symlinks automatically.
	Path string `yaml:"path"`

	// ProcessName, if non-empty, restricts uprobe attachment to processes
	// whose comm name (/proc/<pid>/comm) matches this value.
	// Leave empty to attach system-wide (catches all instances of the binary).
	ProcessName string `yaml:"process_name"`

	// SSLWriteOffset is the file offset (bytes from start of file) of the
	// SSL_write function inside the binary. Required for stripped executables
	// where symbol lookup fails. Set to 0 to attempt auto-detection via the
	// ELF symbol table (works for unstripped or partially-stripped binaries).
	SSLWriteOffset uint64 `yaml:"ssl_write_offset"`

	// SSLReadOffset is the file offset of the SSL_read function.
	// Must be provided together with SSLWriteOffset for stripped binaries.
	SSLReadOffset uint64 `yaml:"ssl_read_offset"`
}

// TLSConfig configures eBPF uprobe-based TLS/SSL interception.
type TLSConfig struct {
	// Enabled activates SSL uprobe interception.
	Enabled bool `yaml:"enabled"`
	// PIDs is a list of process IDs to attach SSL uprobes to.
	// If empty and Enabled is true, attempts are made for all processes using libssl.
	PIDs []int `yaml:"pids"`
	// Processes is a list of process names to attach SSL uprobes to.
	Processes []string `yaml:"processes"`
	// LibSSLPath is the path to libssl.so for symbol resolution.
	// Leave empty to auto-detect from /proc/<pid>/maps.
	LibSSLPath string `yaml:"libssl_path"`
	// BoringSSlExecutables lists executables or libraries with statically embedded
	// or dynamically loaded BoringSSL (e.g. Chromium, Electron, some Node.js builds).
	// These are handled independently of the system libssl.so uprobe path.
	BoringSSlExecutables []BoringSSlExecutable `yaml:"boringssl_executables"`
}

// StreamConfig configures the HTTP event streaming endpoint.
type StreamConfig struct {
	// Enabled activates the HTTP streaming server.
	Enabled bool `yaml:"enabled"`
	// Address is the TCP address to listen on (e.g. "127.0.0.1:8080").
	Address string `yaml:"address"`
	// Path is the HTTP path for the event stream (e.g. "/events").
	Path string `yaml:"path"`
}

// Load reads and parses the YAML config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}

	cfg.applyDefaults()

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// LoadOrDefault loads config from path, or returns a default config on error.
func LoadOrDefault(path string) *Config {
	cfg, err := Load(path)
	if err != nil {
		cfg = defaultConfig()
	}
	return cfg
}

func defaultConfig() *Config {
	cfg := &Config{}
	cfg.applyDefaults()
	// Enable TLS interception by default so the agent works out-of-the-box
	// without a config file.  A config file can override with enabled: false.
	cfg.TLS.Enabled = true
	return cfg
}

func (c *Config) applyDefaults() {
	if c.Interface == "" {
		c.Interface = defaultInterface()
	}
	if len(c.Ports) == 0 {
		c.Ports = []int{80, 443, 8080, 8443}
	}
	if c.Output.MaxSizeMB == 0 {
		c.Output.MaxSizeMB = 100
	}
	if c.Output.MaxAgeDays == 0 {
		c.Output.MaxAgeDays = 7
	}
	if c.Output.MaxBackups == 0 {
		c.Output.MaxBackups = 3
	}
	if !c.Output.Stdout && c.Output.File == "" {
		c.Output.Stdout = true
	}
	if c.EventStream.Address == "" {
		c.EventStream.Address = "127.0.0.1:8080"
	}
	if c.EventStream.Path == "" {
		c.EventStream.Path = "/events"
	}
}

// defaultInterface returns the name of the network interface that carries the
// default route (i.e. the outbound internet interface).  Falls back to "eth0"
// if detection fails so the agent starts rather than panicking.
func defaultInterface() string {
	// Probe by dialling a well-known external address without actually sending
	// any traffic; the OS selects the outbound interface, and we read its name.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "eth0"
	}
	defer conn.Close()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil {
		return "eth0"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "eth0"
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localAddr.IP) {
				return iface.Name
			}
		}
	}
	return "eth0"
}

func (c *Config) validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface must not be empty")
	}
	return nil
}
