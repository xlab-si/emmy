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

// TestInsecureConnection tests whether an insecure connection to the server can be successfully
// established.
func TestInsecureConnection(t *testing.T) {
	cfg := NewConnectionConfig(testGrpcServerEndpoint, make([]byte, 0), true)
	_, err := GetConnection(cfg)
	assert.Nil(t, err, "Insecure connection should be established without errors")
}

// TestValidCertificate tests whether a secure connection to the server is successfully established,
// given that we have a valid CA certificate.
func TestValidCertificate(t *testing.T) {
	caCert, _ := ioutil.ReadFile("testdata/server.pem")
	cfg := NewConnectionConfig(testGrpcServerEndpoint, caCert, false)
	_, err := GetConnection(cfg)
	assert.Nil(t, err, "should finish without error")
}

//TestInvalidFormatCertificate tests client's behavior in case secure connection cannot be
// established due to improper formatting of the provided CA certificate.
func TestInvalidFormatCertificate(t *testing.T) {
	cfg := NewConnectionConfig(testGrpcServerEndpoint, make([]byte, 0), false)
	_, err := GetConnection(cfg)
	assert.NotNil(t, err, "should finish with error because of PEM format issue")
}
