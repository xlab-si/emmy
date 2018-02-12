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
	"testing"

	"io/ioutil"

	"github.com/stretchr/testify/assert"
)

// TestServerNameOverride tests whether a secure connection to the server can be successfully
// established despite byspassing the server hostname == server cert's CN check.
func TestServerNameOverride(t *testing.T) {
	caCert, _ := ioutil.ReadFile("testdata/server.pem")
	cfg := NewConnectionConfig(testGrpcServerEndpoint, "localhost", caCert, 500)
	_, err := GetConnection(cfg)

	assert.Nil(t, err, "connection should be established without errors")
}

// TestWrongServerNameOverride tests the behavior when a secure connection to the server cannot be
// successfully established because serverNameOverride != server cert's CN.
func TestWrongServerNameOverride(t *testing.T) {
	caCert, _ := ioutil.ReadFile("testdata/server.pem")
	cfg := NewConnectionConfig(testGrpcServerEndpoint, "test", caCert, 500)
	_, err := GetConnection(cfg)

	assert.NotNil(t, err, "connection should not be established without an error")
}

// TestValidCertificate tests whether a secure connection to the server is successfully established,
// given that we have a valid CA certificate and that server hostname == server cert's CN check
// is in place.
func TestValidCertificate(t *testing.T) {
	// This caCert is different than the one used by the test server
	caCert, _ := ioutil.ReadFile("testdata/server.pem")
	cfg := NewConnectionConfig(testGrpcServerEndpoint, "", caCert, 500)
	_, err := GetConnection(cfg)

	assert.Nil(t, err, "should finish without error")
}

// TestInvalidCertificate tests the behavior when a secure connection to the server cannot be
// successfully established due because the provided CA certificate is not the one that signed
// server's certificate.
func TestInvalidCertificate(t *testing.T) {
	caCert, _ := ioutil.ReadFile("testdata/server2.pem")
	cfg := NewConnectionConfig(testGrpcServerEndpoint, "", caCert, 500)
	_, err := GetConnection(cfg)

	assert.NotNil(t, err, "should finish with error due to invalid certificate")
}

//TestInvalidFormatCertificate tests client's behavior when secure connection cannot be
// established due to invalid formatting of the provided CA certificate.
func TestInvalidFormatCertificate(t *testing.T) {
	// the caCert parameter to NewConnectionConfig will not be nil, but will be someting that
	// does not conform to the PEM format
	cfg := NewConnectionConfig(testGrpcServerEndpoint, "", make([]byte, 0), 500)
	_, err := GetConnection(cfg)

	assert.NotNil(t, err, "should finish with error because of PEM format issue")
}

// TestNonexistingCertificateFromSysCertPool checks the behavior when a secure connection cannot
// be established because certificate of the CA that signed test server's cert is not in the host
// system's certificate pool.
func TestNonexistingCertificateFromSysCertPool(t *testing.T) {
	cfg := NewConnectionConfig(testGrpcServerEndpoint, "", nil, 500)
	_, err := GetConnection(cfg)

	assert.NotNil(t, err, "should finish with error because server's test cert should"+
		"not be in the host system's certificate pool")
}
