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
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/groups"
	pb "github.com/xlab-si/emmy/protobuf"
)

func testSchnorrEC(n *big.Int, variant pb.SchemaVariant) error {
	c, err := NewSchnorrECClient(testGrpcClientConn, variant, groups.P256, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func TestSchnorrEC(t *testing.T) {
	n := big.NewInt(345345345334)
	desc := "should finish without errors"

	assert.Nil(t, testSchnorrEC(n, pb.SchemaVariant_SIGMA), desc)
	assert.Nil(t, testSchnorrEC(n, pb.SchemaVariant_ZKP), desc)
	assert.Nil(t, testSchnorrEC(n, pb.SchemaVariant_ZKPOK), desc)
}
