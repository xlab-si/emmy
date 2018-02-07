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

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/log"
)

func TestQRProof(t *testing.T) {
	prevLogger := GetLogger()
	SetLogger(log.NewNullLogger())

	group := config.LoadSchnorrGroup()
	y1 := common.GetRandomInt(group.P)

	qrClient, err := NewQRClient(testGrpcClientConn, group, y1)
	if err != nil {
		t.Errorf("Error when initializing NewQRClient")
	}

	proved, err := qrClient.Run()
	if err != nil {
		t.Errorf("Error when proving y is QR")
	}
	SetLogger(prevLogger)

	assert.Equal(t, proved, true, "QRRSA proof does not work correctly")
}
