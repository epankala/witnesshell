package transport

import "crypto/tls"

func clientTLS() *tls.Config {
	return &tls.Config{NextProtos: []string{alpn}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
}
