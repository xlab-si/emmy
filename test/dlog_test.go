package test

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
	"testing"
)

func TestDLogEquality(t *testing.T) {
	dlog := config.LoadDLog("pseudonymsys")

	secret := big.NewInt(213412)
	groupOrder := new(big.Int).Sub(dlog.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)
	g2, _ := common.GetGeneratorOfZnSubgroup(dlog.P, groupOrder, dlog.OrderOfSubgroup)

	t1, _ := dlog.Exponentiate(g1, secret)
	t2, _ := dlog.Exponentiate(g2, secret)
	proved := dlogproofs.RunDLogEquality(secret, g1, g2, t1, t2, dlog)

	assert.Equal(t, proved, true, "DLogEquality does not work correctly")
}

func TestDLogEqualityBlindedTranscript(t *testing.T) {
	dlog := config.LoadDLog("pseudonymsys")

	eProver := dlogproofs.NewDLogEqualityBTranscriptProver(dlog)
	eVerifier := dlogproofs.NewDLogEqualityBTranscriptVerifier(dlog, nil)

	secret := big.NewInt(213412)
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

	g1 := common.NewECGroupElement(g11, g12)
	g2 := common.NewECGroupElement(g21, g22)

	t1 := common.NewECGroupElement(t11, t12)
	t2 := common.NewECGroupElement(t21, t22)

	proved := dlogproofs.RunECDLogEquality(secret, g1, g2, t1, t2, dlog.P256)
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
