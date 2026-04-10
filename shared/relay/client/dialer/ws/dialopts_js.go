//go:build js

package ws

import (
	"crypto/tls"
	"errors"

	"github.com/coder/websocket"
)

func createDialOptions(_ string, _ any, clientCert *tls.Certificate) (*websocket.DialOptions, error) {
	if clientCert != nil {
		return nil, errors.New("relay mTLS client certificates are not supported in WASM builds")
	}
	return &websocket.DialOptions{}, nil
}
