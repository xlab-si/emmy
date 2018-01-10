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
	"github.com/xlab-si/emmy/crypto/groups"
)

func TestDLogEqualityEC(t *testing.T) {
	group := groups.NewECGroup(groups.P256)
	secret := common.GetRandomInt(group.Q)

	r1 := common.GetRandomInt(group.Q)
	r2 := common.GetRandomInt(group.Q)

	g1 := group.ExpBaseG(r1)
	g2 := group.ExpBaseG(r2)

	t1 := group.Exp(g1, secret)
	t2 := group.Exp(g2, secret)

	proved := ProveECDLogEquality(secret, g1, g2, t1, t2, groups.P256)
	assert.Equal(t, proved, true, "DLogEqualityEC does not work correctly")

	eProver := NewECDLogEqualityBTranscriptProver(groups.P256)
	eVerifier := NewECDLogEqualityBTranscriptVerifier(groups.P256, nil)
	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)
	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	_, transcript, G2, T2 := eVerifier.Verify(z)
	valid := VerifyBlindedTranscriptEC(transcript, groups.P256, g1, t1, G2, T2)

	assert.Equal(t, valid, true, "DLogEqualityECBTranscript does not work correctly")

}
