package client

import (
	"crypto/tls"
	"google.golang.org/grpc/credentials"
)

// getTLSClientCredentials generates appropriate TLS credentials that the client can use to
// contact the server via TLS.
// Client credentials are constructed either for secure (in production) or insecure (during
// development) communication with the server
func getTLSClientCredentials(caCertFile string,
	insecure bool) (credentials.TransportCredentials, error) {
	// Do not check server's hostname or CA certificate chain
	// This should only be used for testing & development, when the server uses a self-signed cert
	if insecure {
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		}), nil
	}

	creds, err := credentials.NewClientTLSFromFile(caCertFile, "")
	if err != nil {
		return nil, err
	}

	return creds, err
}
