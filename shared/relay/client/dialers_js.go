//go:build js

package client

import (
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

func (c *Client) getDialers(_ TransportMode) []dialer.DialeFn {
	// JS/WASM build only uses WebSocket transport
	// Note: Client certificates (mTLS) are not supported in WASM builds
	// as the browser controls TLS configuration
	return []dialer.DialeFn{ws.Dialer{}}
}

func (c *Client) baseDialers(_ TransportMode) []dialer.DialeFn {
	return []dialer.DialeFn{ws.Dialer{}}
}
