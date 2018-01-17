/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// getTLSClientCredentials generates appropriate TLS credentials that the client can use to
// contact the server via TLS.
// Client credentials are constructed either for secure (in production) or insecure (during
// development) communication with the server.
func getTLSClientCredentials(caCert []byte,
	insecure bool) (credentials.TransportCredentials, error) {
	// Do not check server's hostname or CA CACertificate chain
	// This should only be used for testing & development, when the server uses a self-signed cert
	if insecure {
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		}), nil
	}

	// When server's hostname or CA certificate chain is to be validated,
	// the client needs to provide the CA certificate in PEM format
	certPool := x509.NewCertPool()
	if success := certPool.AppendCertsFromPEM(caCert); !success {
		return nil, fmt.Errorf("cannot append certs from PEM")
	}

	return credentials.NewClientTLSFromCert(certPool, ""), nil
}
