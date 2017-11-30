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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

// ProveECDLogKnowledge demonstrates how prover can prove the knowledge of log_g1(t1) - that
// means g1^secret = t1 in EC group.
func ProveECDLogKnowledge(secret *big.Int, g1, t1 *types.ECGroupElement, curve groups.ECurve) (bool, error) {
	prover, err := NewSchnorrECProver(curve, types.Sigma)
	if err != nil {
		return false, err
	}
	verifier := NewSchnorrECVerifier(curve, types.Sigma)

	x := prover.GetProofRandomData(secret, g1)
	verifier.SetProofRandomData(x, g1, t1)

	challenge, _ := verifier.GetChallenge()
	z, _ := prover.GetProofData(challenge)
	verified := verifier.Verify(z, nil)
	return verified, nil
}

// TODO: demonstrator for ZKP and ZKPOK

// Note that this is zero knowledge proof (contructed from sigma protocol) -
// this is protocol 6.5.1 from Hazay-Lindell.
//
// It can be turned into zero knowledge proof of knowledge (6.5.4 from Hazay-Lindell) if
// proofOfKnowledge is set to true in third message.
//
// First the prover sends h (h = g^a where a is trapdoor) to the verifier.
// Verifier chooses challenge e and commit to it (sends back c = g^e * h^r1 where r1 is random).
// Prover sends the first message of sigma protocol (g^r2 where r2 is random).
// Verifier decommit to e (sends e and r1).
// Prover sends z = r2 + secret * e.
//
// h -->
// <-- c = g^e * h^r1
// g^r2 -- >
// <-- e, r1
// z = r2 + secret * e -->  (if ZKPOK, trapdoor is sent as well)
type SchnorrECProver struct {
	Group            *groups.ECGroup
	a                *types.ECGroupElement
	secret           *big.Int
	r                *big.Int                        // ProofRandomData
	PedersenReceiver *commitments.PedersenECReceiver // only needed for ZKP and ZKPOK, not for sigma
	protocolType     types.ProtocolType
}

func NewSchnorrECProver(curveType groups.ECurve, protocolType types.ProtocolType) (*SchnorrECProver, error) {
	group := groups.NewECGroup(curveType)
	prover := SchnorrECProver{
		Group:        group,
		protocolType: protocolType,
	}

	if protocolType != types.Sigma {
		prover.PedersenReceiver = commitments.NewPedersenECReceiver(curveType)
	}

	return &prover, nil
}

// Returns pedersenReceiver's h. Verifier needs h to prepare a commitment.
func (prover *SchnorrECProver) GetOpeningMsg() *types.ECGroupElement {
	return prover.PedersenReceiver.GetH()
}

// It contains also value b = a^secret.
func (prover *SchnorrECProver) GetProofRandomData(secret *big.Int,
	a *types.ECGroupElement) *types.ECGroupElement {
	r := common.GetRandomInt(prover.Group.Q)
	prover.r = r
	prover.a = a
	prover.secret = secret
	x := prover.Group.Exp(a, r)
	return x
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w
// and trapdoor in ZKPOK.
func (prover *SchnorrECProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int) {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.Group.Q)

	if prover.protocolType != types.ZKPOK {
		return z, nil
	} else {
		trapdoor := prover.PedersenReceiver.GetTrapdoor()
		return z, trapdoor
	}
}

type SchnorrECVerifier struct {
	Group             *groups.ECGroup
	x                 *types.ECGroupElement
	a                 *types.ECGroupElement
	b                 *types.ECGroupElement
	challenge         *big.Int
	pedersenCommitter *commitments.PedersenECCommitter // not needed in sigma protocol, only in ZKP and ZKPOK
	protocolType      types.ProtocolType
}

func NewSchnorrECVerifier(curveType groups.ECurve, protocolType types.ProtocolType) *SchnorrECVerifier {
	group := groups.NewECGroup(curveType)
	verifier := SchnorrECVerifier{
		Group:        group,
		protocolType: protocolType,
	}

	if protocolType != types.Sigma {
		verifier.pedersenCommitter = commitments.NewPedersenECCommitter(curveType)
	}

	return &verifier
}

// GenerateChallenge is used in ZKP where challenge needs to be
// chosen (and committed to) before sigma protocol starts.
func (verifier *SchnorrECVerifier) GenerateChallenge() *big.Int {
	challenge := common.GetRandomInt(verifier.Group.Q)
	verifier.challenge = challenge
	return challenge
}

func (verifier *SchnorrECVerifier) GetOpeningMsgReply(h *types.ECGroupElement) *types.ECGroupElement {
	verifier.pedersenCommitter.SetH(h) // h = g^a where a is a trapdoor
	challenge := verifier.GenerateChallenge()
	commitment, _ := verifier.pedersenCommitter.GetCommitMsg(challenge)
	return commitment
}

// TODO: t transferred at some other stage?
func (verifier *SchnorrECVerifier) SetProofRandomData(x, a, b *types.ECGroupElement) {
	verifier.x = x
	verifier.a = a
	verifier.b = b
}

// It returns a challenge and commitment to challenge (this latter only for ZKP and ZKPOK).
func (verifier *SchnorrECVerifier) GetChallenge() (*big.Int, *big.Int) {
	if verifier.protocolType == types.Sigma {
		challenge := verifier.GenerateChallenge()
		return challenge, nil
	} else {
		challenge, r2 := verifier.pedersenCommitter.GetDecommitMsg()
		return challenge, r2
	}
}

func (verifier *SchnorrECVerifier) Verify(z *big.Int, trapdoor *big.Int) bool {
	if verifier.protocolType == types.ZKPOK {
		valid := verifier.pedersenCommitter.VerifyTrapdoor(trapdoor)
		if !valid {
			return false
		}
	}
	left := verifier.Group.Exp(verifier.a, z)
	r := verifier.Group.Exp(verifier.b, verifier.challenge)
	right := verifier.Group.Mul(r, verifier.x)

	return types.CmpECGroupElements(left, right)
}
