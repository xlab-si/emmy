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

package dlogproofs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/schnorr"
	"github.com/xlab-si/emmy/crypto/zn"
)

func TestDLogEqualityBlindedTranscript(t *testing.T) {
	schnorrGroup, _ := schnorr.NewGroup(256)
	zp, _ := zn.NewGroupZp(schnorrGroup.P)

	eProver := NewDLogEqualityBTranscriptProver(schnorrGroup)
	eVerifier := NewDLogEqualityBTranscriptVerifier(schnorrGroup, nil)

	secret := common.GetRandomInt(schnorrGroup.Q)
	//groupOrder := new(big.Int).Sub(eProver.Group.P, big.NewInt(1))
	g1, _ := zp.GetGeneratorOfSubgroup(eProver.Group.Q)
	g2, _ := zp.GetGeneratorOfSubgroup(eProver.Group.Q)

	t1 := eProver.Group.Exp(g1, secret)
	t2 := eProver.Group.Exp(g2, secret)

	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	_, transcript, G2, T2 := eVerifier.Verify(z)

	valid := VerifyBlindedTranscript(transcript, eProver.Group, g1, t1, G2, T2)
	assert.Equal(t, valid, true, "DLogEqualityBTranscript does not work correctly")
}
