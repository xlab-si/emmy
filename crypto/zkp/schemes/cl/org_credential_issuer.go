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

package cl

import (
	"crypto/rand"
	"math/big"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/commitments"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type OrgCredentialIssuer struct {
	Org                *Org
	nym                *big.Int
	U                  *big.Int
	nonceOrg           *big.Int
	nymVerifier        *dlogproofs.SchnorrVerifier
	UVerifier          *qrspecialrsaproofs.RepresentationVerifier
	knownAttrs         []*big.Int
	commitmentsOfAttrs []*big.Int
	attrsReceivers     []*commitments.DamgardFujisakiReceiver
	attrsVerifiers     []*commitmentzkp.DFCommitmentOpeningVerifier // user proves the knowledge of commitment opening (committedAttrs)
	// certificate data: TODO: make it a struct
	eInv             *big.Int
	v11              *big.Int
	Q                *big.Int
	A                *big.Int
	credentialProver *qrspecialrsaproofs.RepresentationProver
}

func NewOrgCredentialIssuer(org *Org, nym *big.Int, knownAttrs, commitmentsOfAttrs []*big.Int) (*OrgCredentialIssuer,
	error) {
	attrsReceivers := make([]*commitments.DamgardFujisakiReceiver, len(commitmentsOfAttrs))
	attrsVerifiers := make([]*commitmentzkp.DFCommitmentOpeningVerifier, len(commitmentsOfAttrs))
	for i, attr := range commitmentsOfAttrs {
		receiver, err := commitments.NewDamgardFujisakiReceiverFromParams(org.attributesSpecialRSAPrimes,
			org.PubKey.H, org.PubKey.G, org.ParamSizes.SecParam)
		if err != nil {
			return nil, err
		}
		receiver.SetCommitment(attr)
		attrsReceivers[i] = receiver

		verifier := commitmentzkp.NewDFCommitmentOpeningVerifier(receiver, org.ParamSizes.ChallengeSpace)
		attrsVerifiers[i] = verifier
	}

	return &OrgCredentialIssuer{
		Org:         org,
		nym:         nym,
		nymVerifier: dlogproofs.NewSchnorrVerifier(org.PedersenReceiver.Params.Group),
		UVerifier: qrspecialrsaproofs.NewRepresentationVerifier(org.Group,
			org.ParamSizes.SecParam),
		knownAttrs:         knownAttrs,
		commitmentsOfAttrs: commitmentsOfAttrs,
		attrsReceivers:     attrsReceivers,
		attrsVerifiers:     attrsVerifiers,
	}, nil
}

func (i *OrgCredentialIssuer) GetNonce() *big.Int {
	secParam := big.NewInt(int64(i.Org.ParamSizes.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), secParam, nil)
	n := common.GetRandomInt(b)
	i.nonceOrg = n

	return n
}

func (i *OrgCredentialIssuer) verifyNym(nymProofRandomData, challenge *big.Int,
	nymProofData []*big.Int) bool {
	bases := []*big.Int{
		i.Org.PedersenReceiver.Params.Group.G,
		i.Org.PedersenReceiver.Params.H,
	}
	i.nymVerifier.SetProofRandomData(nymProofRandomData, bases, i.nym)
	i.nymVerifier.SetChallenge(challenge)

	return i.nymVerifier.Verify(nymProofData)
}

func (i *OrgCredentialIssuer) verifyU(UProofRandomData, challenge *big.Int, UProofData []*big.Int) bool {
	// bases are [R_1, ..., R_L, S]
	bases := append(i.Org.PubKey.RsHidden, i.Org.PubKey.S)
	i.UVerifier.SetProofRandomData(UProofRandomData, bases, i.U)
	i.UVerifier.SetChallenge(challenge)

	return i.UVerifier.Verify(UProofData)
}

func (i *OrgCredentialIssuer) verifyChallenge(challenge *big.Int) bool {
	context := i.Org.PubKey.GetContext()
	l := []*big.Int{context, i.U, i.nym, i.nonceOrg}
	l = append(l, i.commitmentsOfAttrs...)
	c := common.Hash(l...)

	return c.Cmp(challenge) == 0
}

func (i *OrgCredentialIssuer) verifyUProofDataLengths(UProofData []*big.Int) bool {
	// boundary for m_tilde
	b_m := i.Org.ParamSizes.AttrBitLen + i.Org.ParamSizes.SecParam + i.Org.ParamSizes.HashBitLen + 2
	// boundary for v1_tilde
	b_v1 := i.Org.ParamSizes.NLength + 2*i.Org.ParamSizes.SecParam + i.Org.ParamSizes.HashBitLen + 1

	exp := big.NewInt(int64(b_m))
	b1 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	exp = big.NewInt(int64(b_v1))
	b2 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	for ind := 0; ind < len(i.Org.PubKey.RsHidden); ind++ {
		if UProofData[ind].Cmp(b1) > 0 {
			return false
		}
	}
	if UProofData[len(i.Org.PubKey.RsHidden)].Cmp(b2) > 0 {
		return false
	}

	return true
}

func (i *OrgCredentialIssuer) verifyCommitmentsOfAttrs(commitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof) bool {
	for i, v := range i.attrsVerifiers {
		v.SetProofRandomData(commitmentsOfAttrsProofs[i].ProofRandomData)
		v.SetChallenge(commitmentsOfAttrsProofs[i].Challenge)
		if !v.Verify(commitmentsOfAttrsProofs[i].ProofData1,
			commitmentsOfAttrsProofs[i].ProofData2) {
			return false
		}
	}

	return true
}

func (i *OrgCredentialIssuer) VerifyCredentialRequest(nymProof *dlogproofs.SchnorrProof, U *big.Int,
	UProof *qrspecialrsaproofs.RepresentationProof,
	commitmentsOfAttrsProofs []*commitmentzkp.DFOpeningProof) bool {
	i.U = U

	return i.verifyNym(nymProof.ProofRandomData, nymProof.Challenge, nymProof.ProofData) &&
		i.verifyU(UProof.ProofRandomData, UProof.Challenge, UProof.ProofData) &&
		i.verifyCommitmentsOfAttrs(commitmentsOfAttrsProofs) &&
		i.verifyChallenge(UProof.Challenge) &&
		i.verifyUProofDataLengths(UProof.ProofData)
}

func (i *OrgCredentialIssuer) IssueCredential(nonceUser *big.Int) (*big.Int, *big.Int, *big.Int,
	*qrspecialrsaproofs.RepresentationProof) {
	exp := big.NewInt(int64(i.Org.ParamSizes.EBitLen - 1))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	var e *big.Int
	for {
		er, _ := rand.Prime(rand.Reader, i.Org.ParamSizes.E1BitLen-1)
		e = new(big.Int).Add(er, b)
		if e.ProbablyPrime(20) { // e needs to be prime
			break
		}
	}

	vr, _ := rand.Prime(rand.Reader, i.Org.ParamSizes.VBitLen-1)
	exp = big.NewInt(int64(i.Org.ParamSizes.VBitLen - 1))
	b = new(big.Int).Exp(big.NewInt(2), exp, nil)
	v11 := new(big.Int).Add(vr, b)

	// denom = U * S^v11 * R_1^attr_1 * ... * R_j^attr_j where only attributes from knownAttrs and committedAttrs
	acc := big.NewInt(1)
	for ind := 0; ind < len(i.knownAttrs); ind++ {
		t1 := i.Org.Group.Exp(i.Org.PubKey.RsKnown[ind], i.knownAttrs[ind])
		acc = i.Org.Group.Mul(acc, t1)
	}

	for ind := 0; ind < len(i.commitmentsOfAttrs); ind++ {
		t1 := i.Org.Group.Exp(i.Org.PubKey.RsCommitted[ind], i.commitmentsOfAttrs[ind])
		acc = i.Org.Group.Mul(acc, t1)
	}

	t := i.Org.Group.Exp(i.Org.PubKey.S, v11) // s^v11
	denom := i.Org.Group.Mul(t, i.U)          // U * s^v11
	denom = i.Org.Group.Mul(denom, acc)       // U * s^v11 * acc
	denomInv := i.Org.Group.Inv(denom)
	Q := i.Org.Group.Mul(i.Org.PubKey.Z, denomInv)

	phiN := new(big.Int).Mul(i.Org.Group.P1, i.Org.Group.Q1)
	eInv := new(big.Int).ModInverse(e, phiN)
	A := i.Org.Group.Exp(Q, eInv)

	i.eInv = eInv
	i.v11 = v11
	i.Q = Q
	i.A = A

	AProof := i.getAProof(nonceUser)

	return A, e, v11, AProof
}

func (i *OrgCredentialIssuer) getAProof(nonceUser *big.Int) *qrspecialrsaproofs.RepresentationProof {
	prover := qrspecialrsaproofs.NewRepresentationProver(i.Org.Group, i.Org.ParamSizes.SecParam,
		[]*big.Int{i.eInv}, []*big.Int{i.Q}, i.A)
	i.credentialProver = prover
	proofRandomData := prover.GetProofRandomData(true)
	// challenge = hash(context||Q||A||AProofRandomData||nonceUser)
	context := i.Org.PubKey.GetContext()
	challenge := common.Hash(context, i.Q, i.A, proofRandomData, nonceUser)
	proofData := prover.GetProofData(challenge)

	return qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData)
}
