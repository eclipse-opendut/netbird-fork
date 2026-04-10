//go:build !js

package ws

import (
	"crypto/tls"
	"net"

	"github.com/coder/websocket"
)

func createDialOptions(serverName string, underlyingOut *net.Conn, clientCert *tls.Certificate) (*websocket.DialOptions, error) {
	return &websocket.DialOptions{
		HTTPClient: httpClientNbDialer(serverName, underlyingOut, clientCert),
	}, nil
}
