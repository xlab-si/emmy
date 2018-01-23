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
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// getTLSCredentials generates TLS credentials that the client can use to contact the
// server via TLS. Server's certificate (in PEM format) will always be validated against the
// provided caCert.
// If serverNameOverride == "", certificate validation will include a check that server's hostname
// 	matches the common name (CN) in server's certificate.
// If serverNameOverride != "", the provided serverNameOverride must match server certificate's
//	CN in order for certificate validation to succeed. This can be used for testing and development
//	purposes, where server's CN does not resolve to a real domain and doesn't.
func getTLSCredentials(caCert []byte, serverNameOverride string) (credentials.TransportCredentials,
	error) {
	certPool := x509.NewCertPool()
	// Try to append the provided caCert to the cert pool
	if success := certPool.AppendCertsFromPEM(caCert); !success {
		return nil, fmt.Errorf("cannot append certs from PEM")
	}

	return credentials.NewClientTLSFromCert(certPool, serverNameOverride), nil
}

// getTLSCredentialsFromSysCertPool retrieves TLS credentials based on host's system certificate
// pool. This function should be used when the client does not provide a specific CA certificate
// for validation of the target server.
func getTLSCredentialsFromSysCertPool() (credentials.TransportCredentials, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve system cert pool (%s)", err)
	}

	return credentials.NewClientTLSFromCert(certPool, ""), nil
}
