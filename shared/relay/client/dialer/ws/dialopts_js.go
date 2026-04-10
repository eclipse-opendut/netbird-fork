//go:build js

package ws

import (
	"crypto/tls"
	"net"

	"github.com/coder/websocket"
)

func createDialOptions(_ string, _ *net.Conn, _ *tls.Certificate) *websocket.DialOptions {
	// WASM version doesn't support HTTPClient or custom TLS config.
	return &websocket.DialOptions{}
}
