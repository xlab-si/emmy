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
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

// ProveDLogKnowledge demonstrates how prover can prove the knowledge of log_g1(t1) - that
// means g1^secret = t1.
func ProveDLogKnowledge(secret, g1, t1 *big.Int, dlog *dlog.ZpDLog) bool {
	prover := NewSchnorrProver(dlog, types.Sigma)
	verifier := NewSchnorrVerifier(dlog, types.Sigma)

	x := prover.GetProofRandomData(secret, g1)
	verifier.SetProofRandomData(x, g1, t1)

	challenge, _ := verifier.GetChallenge()
	z, _ := prover.GetProofData(challenge)
	verified := verifier.Verify(z, nil)
	return verified
}

// TODO: demonstrator for ZKP and ZKPOK

// Proving that it knows w such that g^w = h (mod p).
type SchnorrProver struct {
	DLog             *dlog.ZpDLog
	secret           *big.Int
	a                *big.Int
	r                *big.Int
	PedersenReceiver *commitments.PedersenReceiver // only needed for ZKP and ZKPOK, not for sigma
	protocolType     types.ProtocolType
}

func NewSchnorrProver(dlog *dlog.ZpDLog, protocolType types.ProtocolType) *SchnorrProver {
	var prover SchnorrProver
	prover = SchnorrProver{
		DLog:         dlog,
		protocolType: protocolType,
	}

	if protocolType != types.Sigma {
		// TODO: currently Pedersen is using the same dlog as SchnorrProver, this
		// is because SchnorrVerifier for ZKP/ZKPOK needs to know Pedersen's dlog
		// to generate a challenge and create a commitment
		prover.PedersenReceiver = commitments.NewPedersenReceiverFromExistingDLog(dlog)
	}

	return &prover
}

// Returns pedersenReceiver's h. Verifier needs h to prepare a commitment.
func (prover *SchnorrProver) GetOpeningMsg() *big.Int {
	h := prover.PedersenReceiver.GetH()
	return h
}

// GetProofRandomData sets prover.secret and prover.a, and returns a^r % p where r is random.
func (prover *SchnorrProver) GetProofRandomData(secret, a *big.Int) *big.Int {
	// TODO: name GetProofRandomData is not ok, but I am not sure what would be the best way
	// to fix it.
	// It might be replaced with something that
	// would reflect setting of parameters secret and a. Splitting into two functions is
	// another option, but it would add complexity of the API (for example SetParams necessary to
	// be called before GetProofRandomData). Possible solution would also be to push secret and a
	// into SchnorrProver constructor, but then if SchnorrProver used for two different proofs
	// (two different (secret, a) pairs), its params would need to be reset before proof execution.
	// Thinking of it, this last option might be the one to go, because usually Schnorr is
	// executed once.
	// The problem is the same for all proofs.

	// x = a^r % p, where r is random
	prover.a = a
	prover.secret = secret
	r := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	prover.r = r
	x, _ := prover.DLog.Exponentiate(a, r)

	return x
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w
// and trapdoor in ZKPOK.
func (prover *SchnorrProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int) {
	// z = r + challenge * w
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())

	if prover.protocolType != types.ZKPOK {
		return z, nil
	} else {
		trapdoor := prover.PedersenReceiver.GetTrapdoor()
		return z, trapdoor
	}
}

type SchnorrVerifier struct {
	DLog              *dlog.ZpDLog
	x                 *big.Int
	a                 *big.Int
	b                 *big.Int
	challenge         *big.Int
	pedersenCommitter *commitments.PedersenCommitter // not needed in sigma protocol, only in ZKP and ZKPOK
	protocolType      types.ProtocolType
}

func NewSchnorrVerifier(dlog *dlog.ZpDLog, protocolType types.ProtocolType) *SchnorrVerifier {
	verifier := SchnorrVerifier{
		DLog:         dlog,
		protocolType: protocolType,
	}
	if protocolType != types.Sigma {
		verifier.pedersenCommitter = commitments.NewPedersenCommitter(dlog)
	}
	return &verifier
}

// GenerateChallenge is used in ZKP where challenge needs to be
// chosen (and committed to) before sigma protocol starts.
func (verifier *SchnorrVerifier) GenerateChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
	verifier.challenge = challenge
	return challenge
}

func (verifier *SchnorrVerifier) GetOpeningMsgReply(h *big.Int) *big.Int {
	verifier.pedersenCommitter.SetH(h) // h = g^a where a is a trapdoor
	challenge := verifier.GenerateChallenge()
	commitment, _ := verifier.pedersenCommitter.GetCommitMsg(challenge)
	return commitment
}

// TODO: similar as described above for GetProofRandomData - this one is not setting
// only proofRandomData, thus it might be split (a, b for example set in SchnorrVerifier constructor).
func (verifier *SchnorrVerifier) SetProofRandomData(x, a, b *big.Int) {
	verifier.x = x
	verifier.a = a
	verifier.b = b
}

// It returns a challenge and commitment to challenge (this latter only for ZKP and ZKPOK).
func (verifier *SchnorrVerifier) GetChallenge() (*big.Int, *big.Int) {
	if verifier.protocolType == types.Sigma {
		challenge := verifier.GenerateChallenge()
		return challenge, nil
	} else {
		challenge, r2 := verifier.pedersenCommitter.GetDecommitMsg()
		return challenge, r2
	}
}

// It receives y = r + w * challenge. It returns true if a^y = a^r * (a^secret) ^ challenge, otherwise false.
func (verifier *SchnorrVerifier) Verify(z *big.Int, trapdoor *big.Int) bool {
	if verifier.protocolType == types.ZKPOK {
		valid := verifier.pedersenCommitter.VerifyTrapdoor(trapdoor)
		if !valid {
			return false
		}
	}

	left, _ := verifier.DLog.Exponentiate(verifier.a, z)
	r1, _ := verifier.DLog.Exponentiate(verifier.b, verifier.challenge)
	right, _ := verifier.DLog.Multiply(r1, verifier.x)

	if left.Cmp(right) == 0 {
		return true
	} else {
		return false
	}
}
