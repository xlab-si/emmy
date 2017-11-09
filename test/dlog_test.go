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
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/types"
	"math/big"
	"testing"
)

func TestDLogKnowledge(t *testing.T) {
	dlog := config.LoadDLog("pseudonymsys")

	secret := common.GetRandomInt(dlog.OrderOfSubgroup)
	groupOrder := new(big.Int).Sub(dlog.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)
	t1, _ := dlog.Exponentiate(g1, secret)
	proved := dlogproofs.ProveDLogKnowledge(secret, g1, t1, dlog)

	assert.Equal(t, proved, true, "DLogKnowledge does not work correctly")
}

func TestECDLogKnowledge(t *testing.T) {
	dLog := dlog.NewECDLog(dlog.P256)

	exp1 := common.GetRandomInt(dLog.OrderOfSubgroup)
	a1X, a1Y := dLog.ExponentiateBaseG(exp1)
	a1 := types.NewECGroupElement(a1X, a1Y)

	secret := common.GetRandomInt(dLog.OrderOfSubgroup)
	b1X, b1Y := dLog.Exponentiate(a1X, a1Y, secret)
	b1 := types.NewECGroupElement(b1X, b1Y)

	proved, err := dlogproofs.ProveECDLogKnowledge(secret, a1, b1, dlog.P256)
	if err != nil {
		fmt.Println(err)
		assert.Equal(t, proved, false, "ECDLogEquality proof failed")
	}

	assert.Equal(t, proved, true, "ECDLogEquality does not work correctly")
}

func TestDLogEquality(t *testing.T) {
	dlog := config.LoadDLog("pseudonymsys")

	secret := common.GetRandomInt(dlog.OrderOfSubgroup)
	groupOrder := new(big.Int).Sub(dlog.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)
	g2, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)

	t1, _ := dlog.Exponentiate(g1, secret)
	t2, _ := dlog.Exponentiate(g2, secret)
	proved := dlogproofs.ProveDLogEquality(secret, g1, g2, t1, t2, dlog)

	assert.Equal(t, proved, true, "DLogEquality does not work correctly")
}

func TestDLogEqualityBlindedTranscript(t *testing.T) {
	dlog := config.LoadDLog("pseudonymsys")

	eProver := dlogproofs.NewDLogEqualityBTranscriptProver(dlog)
	eVerifier := dlogproofs.NewDLogEqualityBTranscriptVerifier(dlog, nil)

	secret := common.GetRandomInt(dlog.OrderOfSubgroup)
	groupOrder := new(big.Int).Sub(eProver.DLog.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(eProver.DLog.P, groupOrder, eProver.DLog.OrderOfSubgroup)
	g2, _ := common.GetGeneratorOfZnSubgroup(eProver.DLog.P, groupOrder, eProver.DLog.OrderOfSubgroup)

	t1, _ := eProver.DLog.Exponentiate(g1, secret)
	t2, _ := eProver.DLog.Exponentiate(g2, secret)

	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)

	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	_, transcript, G2, T2 := eVerifier.Verify(z)

	valid := dlogproofs.VerifyBlindedTranscript(transcript, eProver.DLog, g1, t1, G2, T2)
	assert.Equal(t, valid, true, "DLogEqualityBTranscript does not work correctly")
}

func TestDLogEqualityEC(t *testing.T) {
	dLog := dlog.NewECDLog(dlog.P256)
	secret := common.GetRandomInt(dLog.OrderOfSubgroup)

	r1 := common.GetRandomInt(dLog.OrderOfSubgroup)
	r2 := common.GetRandomInt(dLog.OrderOfSubgroup)

	g11, g12 := dLog.ExponentiateBaseG(r1)
	g21, g22 := dLog.ExponentiateBaseG(r2)

	t11, t12 := dLog.Exponentiate(g11, g12, secret)
	t21, t22 := dLog.Exponentiate(g21, g22, secret)

	g1 := types.NewECGroupElement(g11, g12)
	g2 := types.NewECGroupElement(g21, g22)

	t1 := types.NewECGroupElement(t11, t12)
	t2 := types.NewECGroupElement(t21, t22)

	proved := dlogproofs.ProveECDLogEquality(secret, g1, g2, t1, t2, dlog.P256)
	assert.Equal(t, proved, true, "DLogEqualityEC does not work correctly")

	eProver := dlogproofs.NewECDLogEqualityBTranscriptProver(dlog.P256)
	eVerifier := dlogproofs.NewECDLogEqualityBTranscriptVerifier(dlog.P256, nil)
	x1, x2 := eProver.GetProofRandomData(secret, g1, g2)
	challenge := eVerifier.GetChallenge(g1, g2, t1, t2, x1, x2)
	z := eProver.GetProofData(challenge)
	_, transcript, G2, T2 := eVerifier.Verify(z)
	valid := dlogproofs.VerifyBlindedTranscriptEC(transcript, dlog.P256, g1, t1, G2, T2)

	assert.Equal(t, valid, true, "DLogEqualityECBTranscript does not work correctly")

}

func TestPartialDLogKnowledge(t *testing.T) {
	dlog := config.LoadDLog("pseudonymsys")

	secret1 := common.GetRandomInt(dlog.OrderOfSubgroup)
	x := common.GetRandomInt(dlog.OrderOfSubgroup)

	groupOrder := new(big.Int).Sub(dlog.P, big.NewInt(1))
	a1, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)
	a2, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)

	//b1, _ := dlog.Exponentiate(a1, secret1)
	// we pretend that we don't know x:
	b2, _ := dlog.Exponentiate(a2, x)
	proved := dlogproofs.ProvePartialDLogKnowledge(dlog, secret1, a1, a2, b2)

	assert.Equal(t, proved, true, "ProvePartialDLogKnowledge does not work correctly")
}

func TestPartialECDLogKnowledge(t *testing.T) {
	dlog := dlog.NewECDLog(dlog.P256)

	exp1 := common.GetRandomInt(dlog.OrderOfSubgroup)
	exp2 := common.GetRandomInt(dlog.OrderOfSubgroup)
	a1X, a1Y := dlog.ExponentiateBaseG(exp1)
	a1 := types.NewECGroupElement(a1X, a1Y)
	a2X, a2Y := dlog.ExponentiateBaseG(exp2)
	a2 := types.NewECGroupElement(a2X, a2Y)

	secret1 := common.GetRandomInt(dlog.OrderOfSubgroup)
	x := common.GetRandomInt(dlog.OrderOfSubgroup)

	//b1X, b1Y := dlog.ExponentiateBaseG(secret1)
	// we pretend that we don't know x:
	b2X, b2Y := dlog.ExponentiateBaseG(x)
	b2 := types.NewECGroupElement(b2X, b2Y)

	proved := dlogproofs.ProvePartialECDLogKnowledge(dlog, secret1, a1, a2, b2)

	assert.Equal(t, proved, true, "ProvePartialECDLogKnowledge does not work correctly")
}
