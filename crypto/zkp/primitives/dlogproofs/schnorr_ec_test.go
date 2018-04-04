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

// TestDLogKnowledgeEC demonstrates how prover can prove the knowledge of log_g1(t1) - that
// means g1^secret = t1 in EC group.
func TestDLogKnowledgeEC(t *testing.T) {
	group := groups.NewECGroup(groups.P256)
	exp1 := common.GetRandomInt(group.Q)
	a1 := group.ExpBaseG(exp1)
	secret := common.GetRandomInt(group.Q)
	b1 := group.Exp(a1, secret)

	prover := NewSchnorrECProver(groups.P256)
	verifier := NewSchnorrECVerifier(groups.P256)

	x := prover.GetProofRandomData(secret, a1)
	verifier.SetProofRandomData(x, a1, b1)

	challenge := verifier.GetChallenge()
	z := prover.GetProofData(challenge)
	verified := verifier.Verify(z)

	assert.Equal(t, verified, true, "ECDLogEquality does not work correctly")
}
