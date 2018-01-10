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

	"github.com/magiconair/properties/assert"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/groups"
	pb "github.com/xlab-si/emmy/protobuf"
)

func testSchnorr(n *big.Int, group *groups.SchnorrGroup, variant pb.SchemaVariant) error {
	c, err := NewSchnorrClient(testGrpcClientConn, variant, group, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func TestSchnorr(t *testing.T) {
	group := config.LoadGroup("schnorr")
	n := big.NewInt(345345345334)

	var tests = []struct {
		n       *big.Int
		variant pb.SchemaVariant
		res     error
	}{
		{n, pb.SchemaVariant_SIGMA, nil},
		{n, pb.SchemaVariant_ZKP, nil},
		{n, pb.SchemaVariant_ZKPOK, nil},
	}

	for _, test := range tests {
		c, err := NewSchnorrClient(testGrpcClientConn, test.variant, group, test.n)
		if err != nil {
			t.Errorf("Error in NewSchnorrClient: %v", err)
		}
		res := c.Run()
		assert.Equal(t, res, test.res)
	}
}
