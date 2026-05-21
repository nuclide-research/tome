package corpus

// Platform is a single AI/ML infrastructure platform profile from the embedded corpus.
type Platform struct {
	Platform          string      `json:"platform"`
	DisplayName       string      `json:"display_name"`
	Category          string      `json:"category"`
	DefaultPorts      []int       `json:"default_ports"`
	APIPaths          []string    `json:"api_paths"`
	AuthDefault       string      `json:"auth_default"`
	AuthConfigEnv     []string    `json:"auth_config_env"`
	DefaultCreds      []Cred      `json:"default_creds"`
	InstallTell       string      `json:"install_tell"`
	MisconfigPatterns []string    `json:"misconfig_patterns"`
	Fingerprint       Fingerprint `json:"fingerprint"`
	ShodanDorks       ShodanDorks `json:"shodan_dorks"`
	DeploymentTells   []string    `json:"deployment_tells"`
	PivotPaths        []string    `json:"pivot_paths"`
	Vulnerabilities   []string    `json:"vulnerabilities"`
	Sources           []string    `json:"sources"`
}

// Cred is a known default credential pair for a platform.
type Cred struct {
	User    string `json:"user"`
	Pass    string `json:"pass"`
	Context string `json:"context"`
}

// Fingerprint holds passive Shodan filter strings and an active HTTP probe spec.
type Fingerprint struct {
	Passive     []string    `json:"passive"`
	ActiveProbe ActiveProbe `json:"active_probe"`
}

// ActiveProbe defines an HTTP check for live target verification (--active only).
type ActiveProbe struct {
	Path               string   `json:"path"`
	Method             string   `json:"method"`
	ResponseMarkers    []string `json:"response_markers"`
	FalsePositiveCheck string   `json:"false_positive_check"`
}

// ShodanDorks holds dork strings at three specificity tiers.
type ShodanDorks struct {
	Basic   string `json:"basic"`
	Strict  string `json:"strict"`
	Version string `json:"version"`
}

// Finding is the output record from tome scan.
type Finding struct {
	Platform        string   `json:"platform"`
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	DiscoveryMethod string   `json:"discovery_method"`
	AuthRequired    bool     `json:"auth_required"`
	Version         string   `json:"version,omitempty"`
	Verified        bool     `json:"verified"`
	Confidence      float64  `json:"confidence"`
	ActiveProbeUsed bool     `json:"active_probe_used"`
	PivotPaths      []string `json:"pivot_paths,omitempty"`
}

// ProbeConfig is the aimap-compatible output of tome probe.
type ProbeConfig struct {
	Platform            string   `json:"platform"`
	Port                int      `json:"port"`
	ProbePath           string   `json:"probe_path"`
	ResponseMarkers     []string `json:"response_markers"`
	ConfidenceThreshold float64  `json:"confidence_threshold"`
}
