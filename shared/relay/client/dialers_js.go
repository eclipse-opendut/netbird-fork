//go:build js

package client

import (
	"github.com/netbirdio/netbird/shared/relay/client/dialer"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
)

func (c *Client) getDialers(_ TransportMode) []dialer.DialeFn {
	return []dialer.DialeFn{ws.Dialer{ClientCert: c.clientCert}}
}

func (c *Client) baseDialers(_ TransportMode) []dialer.DialeFn {
	return []dialer.DialeFn{ws.Dialer{ClientCert: c.clientCert}}
}
