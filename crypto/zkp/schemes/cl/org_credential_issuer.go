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

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
)

type OrgCredentialIssuer struct {
	Org         *Org
	nym         *big.Int
	U           *big.Int
	n1          *big.Int
	nymVerifier *dlogproofs.SchnorrVerifier
	UVerifier   *qrspecialrsaproofs.RepresentationVerifier
	// certificate data: TODO: make it a struct
	eInv             *big.Int
	v11              *big.Int
	Q                *big.Int
	A                *big.Int
	credentialProver *qrspecialrsaproofs.RepresentationProver
}

func NewOrgCredentialIssuer(org *Org, nym, U *big.Int) *OrgCredentialIssuer {
	return &OrgCredentialIssuer{
		Org:         org,
		nym:         nym,
		U:           U,
		nymVerifier: dlogproofs.NewSchnorrVerifier(org.PedersenReceiver.Params.Group),
		UVerifier: qrspecialrsaproofs.NewRepresentationVerifier(org.Group,
			org.ParamSizes.SecParam),
	}
}

func (i *OrgCredentialIssuer) GetNonce() *big.Int {
	secParam := big.NewInt(int64(i.Org.ParamSizes.SecParam))
	b := new(big.Int).Exp(big.NewInt(2), secParam, nil)
	n := common.GetRandomInt(b)
	i.n1 = n
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
	bases := append(i.Org.PubKey.RsKnown, i.Org.PubKey.S)
	i.UVerifier.SetProofRandomData(UProofRandomData, bases, i.U)
	i.UVerifier.SetChallenge(challenge)
	return i.UVerifier.Verify(UProofData)
}

func (i *OrgCredentialIssuer) verifyChallenge(challenge *big.Int) bool {
	context := i.Org.PubKey.GetContext()
	c := common.Hash(context, i.U, i.nym, i.n1)
	return c.Cmp(challenge) == 0
}

func (i *OrgCredentialIssuer) verifyUProofDataLengths(UProofData []*big.Int) bool {
	// boundary for m_tilde
	b_m := i.Org.ParamSizes.AttrBitLen + i.Org.ParamSizes.SecParam + i.Org.ParamSizes.HashBitLen + 2
	// boundary for v1_tilde
	b_v1 := i.Org.ParamSizes.NLength + 2* i.Org.ParamSizes.SecParam + i.Org.ParamSizes.HashBitLen + 1

	exp := big.NewInt(int64(b_m))
	b1 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	exp = big.NewInt(int64(b_v1))
	b2 := new(big.Int).Exp(big.NewInt(2), exp, nil)

	for ind := 0; ind < len(i.Org.PubKey.RsKnown); ind++ {
		if UProofData[ind].Cmp(b1) > 0 {
			return false
		}
	}
	if UProofData[len(i.Org.PubKey.RsKnown)].Cmp(b2) > 0 {
		return false
	}
	return true
}

func (v *OrgCredentialIssuer) VerifyCredentialRequest(nymProof *dlogproofs.SchnorrProof,
	UProof *qrspecialrsaproofs.RepresentationProof) bool {
	return v.verifyNym(nymProof.ProofRandomData, nymProof.Challenge, nymProof.ProofData) &&
		v.verifyU(UProof.ProofRandomData, UProof.Challenge, UProof.ProofData) &&
		v.verifyChallenge(UProof.Challenge) &&
		v.verifyUProofDataLengths(UProof.ProofData)
}

func (i *OrgCredentialIssuer) IssueCredential(knownAttrs []*big.Int, n2 *big.Int) (*big.Int, *big.Int, *big.Int,
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

	// num = Z * R_1^attr_1 * ... * R_j^attr_j where only attributes from A_k (known)
	// denom = U * S^v11
	acc := big.NewInt(1)
	for ind := 0; ind < len(knownAttrs); ind++ {
		t1 := i.Org.Group.Exp(i.Org.PubKey.RsKnown[ind], knownAttrs[ind]) // TODO: R_list should be replaced with those that correspond to A_k
		acc = i.Org.Group.Mul(acc, t1)
	}
	num := i.Org.Group.Mul(i.Org.PubKey.Z, acc)

	t := i.Org.Group.Exp(i.Org.PubKey.S, v11) // s^v11
	denom := i.Org.Group.Mul(t, i.U)          // U * s^v11
	denomInv := i.Org.Group.Inv(denom)
	Q := i.Org.Group.Mul(num, denomInv)

	phiN := new(big.Int).Mul(i.Org.Group.P1, i.Org.Group.Q1)
	eInv := new(big.Int).ModInverse(e, phiN)
	A := i.Org.Group.Exp(Q, eInv)

	i.eInv = eInv
	i.v11 = v11
	i.Q = Q
	i.A = A

	AProof := i.getAProof(n2)

	return A, e, v11, AProof
}

func (i *OrgCredentialIssuer) getAProof(n2 *big.Int) *qrspecialrsaproofs.RepresentationProof {
	prover := qrspecialrsaproofs.NewRepresentationProver(i.Org.Group, i.Org.ParamSizes.SecParam,
		[]*big.Int{i.eInv}, []*big.Int{i.Q}, i.A)
	i.credentialProver = prover
	proofRandomData := prover.GetProofRandomData(true)
	// challenge = hash(context||Q||A||AProofRandomData||n2)
	context := i.Org.PubKey.GetContext()
	challenge := common.Hash(context, i.Q, i.A, proofRandomData, n2)
	proofData := prover.GetProofData(challenge)

	return qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData)
}
