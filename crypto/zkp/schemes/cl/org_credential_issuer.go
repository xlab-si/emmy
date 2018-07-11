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
	credentialProver   *qrspecialrsaproofs.RepresentationProver
}

func NewOrgCredentialIssuer(org *Org, nym *big.Int, knownAttrs, commitmentsOfAttrs []*big.Int) (*OrgCredentialIssuer,
	error) {
	attrsReceivers := make([]*commitments.DamgardFujisakiReceiver, len(commitmentsOfAttrs))
	attrsVerifiers := make([]*commitmentzkp.DFCommitmentOpeningVerifier, len(commitmentsOfAttrs))
	for i, attr := range commitmentsOfAttrs {
		receiver, err := commitments.NewDamgardFujisakiReceiverFromParams(
			org.SecKey.AttributesSpecialRSAPrimes, org.PubKey.G, org.PubKey.H, org.Params.SecParam)
		if err != nil {
			return nil, err
		}
		receiver.SetCommitment(attr)
		attrsReceivers[i] = receiver

		verifier := commitmentzkp.NewDFCommitmentOpeningVerifier(receiver, org.Params.ChallengeSpace)
		attrsVerifiers[i] = verifier
	}

	return &OrgCredentialIssuer{
		Org:         org,
		nym:         nym,
		nymVerifier: dlogproofs.NewSchnorrVerifier(org.PedersenReceiver.Params.Group),
		UVerifier: qrspecialrsaproofs.NewRepresentationVerifier(org.Group,
			org.Params.SecParam),
		knownAttrs:         knownAttrs,
		commitmentsOfAttrs: commitmentsOfAttrs,
		attrsReceivers:     attrsReceivers,
		attrsVerifiers:     attrsVerifiers,
	}, nil
}

func (i *OrgCredentialIssuer) verifyNym(nymProof *dlogproofs.SchnorrProof) bool {
	bases := []*big.Int{
		i.Org.PedersenReceiver.Params.Group.G,
		i.Org.PedersenReceiver.Params.H,
	}
	i.nymVerifier.SetProofRandomData(nymProof.ProofRandomData, bases, i.nym)
	i.nymVerifier.SetChallenge(nymProof.Challenge)

	return i.nymVerifier.Verify(nymProof.ProofData)
}

func (i *OrgCredentialIssuer) verifyU(UProof *qrspecialrsaproofs.RepresentationProof) bool {
	// bases are [R_1, ..., R_L, S]
	bases := append(i.Org.PubKey.RsHidden, i.Org.PubKey.S)
	i.UVerifier.SetProofRandomData(UProof.ProofRandomData, bases, i.U)
	i.UVerifier.SetChallenge(UProof.Challenge)

	return i.UVerifier.Verify(UProof.ProofData)
}

func (i *OrgCredentialIssuer) verifyChallenge(challenge *big.Int) bool {
	context := i.Org.PubKey.GetContext()
	l := []*big.Int{context, i.U, i.nym, i.Org.credentialIssueNonceOrg}
	l = append(l, i.commitmentsOfAttrs...)
	c := common.Hash(l...)

	return c.Cmp(challenge) == 0
}

func (i *OrgCredentialIssuer) verifyUProofDataLengths(UProofData []*big.Int) bool {
	// boundary for m_tilde
	b_m := i.Org.Params.AttrBitLen + i.Org.Params.SecParam + i.Org.Params.HashBitLen + 2
	// boundary for v1_tilde
	b_v1 := i.Org.Params.NLength + 2*i.Org.Params.SecParam + i.Org.Params.HashBitLen + 1

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

func (i *OrgCredentialIssuer) VerifyCredentialRequest(cr *CredentialRequest) bool {
	i.U = cr.U

	return i.verifyNym(cr.NymProof) &&
		i.verifyU(cr.UProof) &&
		i.verifyCommitmentsOfAttrs(cr.CommitmentsOfAttrsProofs) &&
		i.verifyChallenge(cr.UProof.Challenge) &&
		i.verifyUProofDataLengths(cr.UProof.ProofData)
}

func (i *OrgCredentialIssuer) chooseCredentialRandoms() (*big.Int, *big.Int) {
	exp := big.NewInt(int64(i.Org.Params.EBitLen - 1))
	b := new(big.Int).Exp(big.NewInt(2), exp, nil)
	var e *big.Int
	for {
		er, _ := rand.Prime(rand.Reader, i.Org.Params.E1BitLen-1)
		e = new(big.Int).Add(er, b)
		if e.ProbablyPrime(20) { // e needs to be prime
			break
		}
	}

	vr, _ := rand.Prime(rand.Reader, i.Org.Params.VBitLen-1)
	exp = big.NewInt(int64(i.Org.Params.VBitLen - 1))
	b = new(big.Int).Exp(big.NewInt(2), exp, nil)
	v11 := new(big.Int).Add(vr, b)

	return e, v11
}

func (i *OrgCredentialIssuer) IssueCredential(nonceUser *big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof, error) {
	e, v11 := i.chooseCredentialRandoms()

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

	context := i.Org.PubKey.GetContext()
	AProof := i.getAProof(nonceUser, context, eInv, Q, A)
	receiverRecord := NewReceiverRecord(i.knownAttrs, i.commitmentsOfAttrs, Q, v11, context)
	i.Org.receiverRecords[i.nym] = receiverRecord

	err := i.Org.dbManager.SetReceiverRecord(i.nym, receiverRecord)
	if err != nil {
		return nil, nil, err
	}

	return NewCredential(A, e, v11), AProof, nil
}

func (i *OrgCredentialIssuer) getAProof(nonceUser, context, eInv, Q, A *big.Int) *qrspecialrsaproofs.RepresentationProof {
	prover := qrspecialrsaproofs.NewRepresentationProver(i.Org.Group, i.Org.Params.SecParam,
		[]*big.Int{eInv}, []*big.Int{Q}, A)
	i.credentialProver = prover
	proofRandomData := prover.GetProofRandomData(true)
	// challenge = hash(context||Q||A||AProofRandomData||nonceUser)
	challenge := common.Hash(context, Q, A, proofRandomData, nonceUser)
	proofData := prover.GetProofData(challenge)

	return qrspecialrsaproofs.NewRepresentationProof(proofRandomData, challenge, proofData)
}

func (i *OrgCredentialIssuer) UpdateCredential(nym, nonceUser *big.Int, newKnownAttrs []*big.Int) (*Credential,
	*qrspecialrsaproofs.RepresentationProof, error) {

	rec, err := i.Org.dbManager.GetReceiverRecord(nym)
	if err != nil {
		return nil, nil, err
	}

	e, v11 := i.chooseCredentialRandoms()
	v11Diff := new(big.Int).Sub(v11, rec.V11)

	acc := big.NewInt(1)
	for ind := 0; ind < len(i.knownAttrs); ind++ {
		t1 := i.Org.Group.Exp(i.Org.PubKey.RsKnown[ind],
			new(big.Int).Sub(newKnownAttrs[ind], rec.KnownAttrs[ind]))
		acc = i.Org.Group.Mul(acc, t1)
	}
	t := i.Org.Group.Exp(i.Org.PubKey.S, v11Diff)
	denom := i.Org.Group.Mul(acc, t)
	denomInv := i.Org.Group.Inv(denom)
	newQ := i.Org.Group.Mul(rec.Q, denomInv)

	phiN := new(big.Int).Mul(i.Org.Group.P1, i.Org.Group.Q1)
	eInv := new(big.Int).ModInverse(e, phiN)
	newA := i.Org.Group.Exp(newQ, eInv)

	context := i.Org.PubKey.GetContext()
	AProof := i.getAProof(nonceUser, context, eInv, newQ, newA)
	// currently commitmentsOfAttrs cannot be updated
	rec = NewReceiverRecord(newKnownAttrs, rec.CommitmentsOfAttrs, newQ, v11, context)
	i.Org.receiverRecords[i.nym] = rec

	return NewCredential(newA, e, v11), AProof, nil
}
