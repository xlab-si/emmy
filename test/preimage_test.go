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

package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/preimage"
)

func TestHomomorphismPreimage(t *testing.T) {
	homomorphism, _, H, _, err := commitments.GenerateRSABasedQOneWay(1024)
	if err != nil {
		t.Errorf("Error when generating RSABasedQOneWay homomorphism")
	}
	v := H.GetRandomElement()
	u := homomorphism(v)

	proved := preimage.ProveHomomorphismPreimageKnowledge(homomorphism, H, u, v, 80)

	assert.Equal(t, true, proved, "HomomorphismPreimage proof does not work correctly")
}
