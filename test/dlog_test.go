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
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"math/big"
	"testing"
)

func TestDLogKnowledge(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")

	secret := common.GetRandomInt(group.Q)
	groupOrder := new(big.Int).Sub(group.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)
	t1 := group.Exp(g1, secret)
	proved := dlogproofs.ProveDLogKnowledge(secret, g1, t1, group)

	assert.Equal(t, proved, true, "DLogKnowledge does not work correctly")
}

func TestECDLogKnowledge(t *testing.T) {
	group := groups.NewECGroup(groups.P256)

	exp1 := common.GetRandomInt(group.Q)
	a1 := group.ExpBaseG(exp1)

	secret := common.GetRandomInt(group.Q)
	b1 := group.Exp(a1, secret)

	proved, err := dlogproofs.ProveECDLogKnowledge(secret, a1, b1, groups.P256)
	if err != nil {
		fmt.Println(err)
		assert.Equal(t, proved, false, "ECDLogEquality proof failed")
	}

	assert.Equal(t, proved, true, "ECDLogEquality does not work correctly")
}

func TestDLogEquality(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")

	secret := common.GetRandomInt(group.Q)
	groupOrder := new(big.Int).Sub(group.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)
	g2, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)

	t1 := group.Exp(g1, secret)
	t2 := group.Exp(g2, secret)
	proved := dlogproofs.ProveDLogEquality(secret, g1, g2, t1, t2, group)

	assert.Equal(t, proved, true, "DLogEquality does not work correctly")
}

func TestDLogEqualityBlindedTranscript(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")

	eProver := dlogproofs.NewDLogEqualityBTranscriptProver(group)
	eVerifier := dlogproofs.NewDLogEqualityBTranscriptVerifier(group, nil)

	secret := common.GetRandomInt(group.Q)
	groupOrder := new(big.Int).Sub(eProver.Group.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(eProver.Group.P, groupOrder, eProver.Group.Q)
	g2, _ := common.GetGeneratorOfZnSubgroup(eProver.Group.P, groupOrder, eProver.Group.Q)

	t1 := eProver.Group.Exp(g1, secret)
	t2 := eProver.Group.Exp(g2, secret)

	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	_, transcript, G2, T2 := eVerifier.Verify(z)

	valid := dlogproofs.VerifyBlindedTranscript(transcript, eProver.Group, g1, t1, G2, T2)
	assert.Equal(t, valid, true, "DLogEqualityBTranscript does not work correctly")
}

func TestDLogEqualityEC(t *testing.T) {
	group := groups.NewECGroup(groups.P256)
	secret := common.GetRandomInt(group.Q)

	r1 := common.GetRandomInt(group.Q)
	r2 := common.GetRandomInt(group.Q)

	g1 := group.ExpBaseG(r1)
	g2 := group.ExpBaseG(r2)

	t1 := group.Exp(g1, secret)
	t2 := group.Exp(g2, secret)

	proved := dlogproofs.ProveECDLogEquality(secret, g1, g2, t1, t2, groups.P256)
	assert.Equal(t, proved, true, "DLogEqualityEC does not work correctly")

	eProver := dlogproofs.NewECDLogEqualityBTranscriptProver(groups.P256)
	eVerifier := dlogproofs.NewECDLogEqualityBTranscriptVerifier(groups.P256, nil)
	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)
	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	_, transcript, G2, T2 := eVerifier.Verify(z)
	valid := dlogproofs.VerifyBlindedTranscriptEC(transcript, groups.P256, g1, t1, G2, T2)

	assert.Equal(t, valid, true, "DLogEqualityECBTranscript does not work correctly")

}

func TestPartialDLogKnowledge(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")

	secret1 := common.GetRandomInt(group.Q)
	x := common.GetRandomInt(group.Q)

	groupOrder := new(big.Int).Sub(group.P, big.NewInt(1))
	a1, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)
	a2, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)

	//b1, _ := dlog.Exponentiate(a1, secret1)
	// we pretend that we don't know x:
	b2 := group.Exp(a2, x)
	proved := dlogproofs.ProvePartialDLogKnowledge(group, secret1, a1, a2, b2)

	assert.Equal(t, proved, true, "ProvePartialDLogKnowledge does not work correctly")
}

func TestPartialECDLogKnowledge(t *testing.T) {
	group := groups.NewECGroup(groups.P256)

	exp1 := common.GetRandomInt(group.Q)
	exp2 := common.GetRandomInt(group.Q)
	a1 := group.ExpBaseG(exp1)
	a2 := group.ExpBaseG(exp2)

	secret1 := common.GetRandomInt(group.Q)
	x := common.GetRandomInt(group.Q)

	//b1X, b1Y := dlog.ExponentiateBaseG(secret1)
	// we pretend that we don't know x:
	b2 := group.ExpBaseG(x)

	proved := dlogproofs.ProvePartialECDLogKnowledge(group, secret1, a1, a2, b2)

	assert.Equal(t, proved, true, "ProvePartialECDLogKnowledge does not work correctly")
}
