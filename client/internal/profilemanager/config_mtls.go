package profilemanager

import (
	"crypto/tls"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// MTLSConfig holds the paths to a client certificate/key pair and the loaded certificate.
// The KeyPair field is populated at runtime from the paths and is never persisted.
type MTLSConfig struct {
	CertPath string           `json:",omitempty"`
	KeyPath  string           `json:",omitempty"`
	KeyPair  *tls.Certificate `json:"-"`
}

// IsZero reports whether the persisted mTLS config has any configured paths.
func (c MTLSConfig) IsZero() bool {
	return c.CertPath == "" && c.KeyPath == ""
}

// migrateLegacyClientCertFields copies the old flat ClientCertPath / ClientCertKeyPath fields
// into the IDPClientCert sub-struct and keeps the legacy fields populated for downgrade safety.
// Returns true if a migration was performed.
func (c *Config) migrateLegacyClientCertFields() bool {
	if c.ClientCertPath == "" && c.ClientCertKeyPath == "" {
		return false
	}
	log.Warn("config contains deprecated ClientCertPath/ClientCertKeyPath fields, migrating to IDPClientCert")
	if c.IDPClientCert.CertPath == "" {
		c.IDPClientCert.CertPath = c.ClientCertPath
	}
	if c.IDPClientCert.KeyPath == "" {
		c.IDPClientCert.KeyPath = c.ClientCertKeyPath
	}
	return true
}

// syncLegacyClientCertFields mirrors the IDP mTLS paths into the deprecated flat fields so a
// downgraded client can still read the config.
func (c *Config) syncLegacyClientCertFields() bool {
	if c.ClientCertPath == c.IDPClientCert.CertPath && c.ClientCertKeyPath == c.IDPClientCert.KeyPath {
		return false
	}

	c.ClientCertPath = c.IDPClientCert.CertPath
	c.ClientCertKeyPath = c.IDPClientCert.KeyPath
	return true
}

// applyMTLSCertKeyPair updates the cert/key paths on config from the given input values,
// resets and reloads the cached TLS certificate pair.
// If only CertPath is set, it is used for both the certificate and private key so a combined
// PEM file works without duplicating the path in the config.
// It returns whether any field was updated and any error encountered.
func applyMTLSCertKeyPair(config *MTLSConfig, input MTLSConfig) (updated bool, err error) {
	if input.KeyPath != "" {
		config.KeyPath = input.KeyPath
		updated = true
	}

	if input.CertPath != "" {
		config.CertPath = input.CertPath
		updated = true
	}

	// reset cached pair before reloading
	config.KeyPair = nil
	if config.CertPath == "" && config.KeyPath != "" {
		return updated, fmt.Errorf("CertPath must be set when KeyPath is configured")
	}
	if config.CertPath != "" {
		keyPath := config.KeyPath
		if keyPath == "" {
			keyPath = config.CertPath
		}

		cert, err := tls.LoadX509KeyPair(config.CertPath, keyPath)
		if err != nil {
			return updated, fmt.Errorf("failed to load mTLS cert/key pair: %w", err)
		}
		config.KeyPair = &cert
		log.Info("Loaded mTLS cert/key pair.")
	}

	return updated, nil
}
