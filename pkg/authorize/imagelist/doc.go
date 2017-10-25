package imagelist

import "time"

const (
	// Name is the name of the authorizer
	Name = "imagelist"
)

// Config is the configuration for the service
type Config struct {
	// CacheFailure indicates we shoud cache failures for x duration
	CacheFailure time.Duration `yaml:"cache-failure" json:"cache-failure"`
	// CacheSuccess indicates we should cache successful requests for x duration
	CacheSuccess time.Duration `yaml:"cache-success" json:"cache-success"`
	// ClientCA is the path for a CA file
	ClientCA string `yaml:"client-ca" json:"client-ca"`
	// ClientCertificateCert is the path to a client certificate to use
	ClientCertificateCert string `yaml:"client-cert" json:"client-cert"`
	// ClientCertificateKey is the path to a client certificate to use
	ClientCertificateKey string `yaml:"client-key" json:"client-key"`
	// EndpointURL is the external endpoint to call
	EndpointURL string `yaml:"endpoint-url" json:"endpoint-url"`
	// SkipTLSVerify indicated we skip the TLS for the external endpoint
	SkipTLSVerify bool `yaml:"skip-tls-verify" json:"skip-tls-verify"`
	// IgnoredNamespaces is a list namespaces to ignore
	IgnoreNamespaces []string `yaml:"ignore-namespaces" json:"ignore-namespaces"`
	// Timeout is the duration between timing out
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	// Token is a bearer token to use on requests
	Token string `yaml:"token" json:"token"`
}

// NewDefaultConfig returns a default config
func NewDefaultConfig() *Config {
	return &Config{
		CacheFailure:     time.Duration(1 * time.Minute),
		CacheSuccess:     time.Duration(5 * time.Minute),
		IgnoreNamespaces: []string{"kube-system", "kube-admission", "kube-public"},
		Timeout:          time.Duration(5 * time.Second),
	}
}
