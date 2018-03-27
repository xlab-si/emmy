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

package client

import (
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/protocoltypes"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
)

type PseudonymsysClientEC struct {
	genericClient
	grpcClient pb.PseudonymSystemClient
	curve      groups.ECurve
}

func NewPseudonymsysClientEC(conn *grpc.ClientConn, curve groups.ECurve) (*PseudonymsysClientEC, error) {
	return &PseudonymsysClientEC{
		genericClient: newGenericClient(),
		grpcClient:    pb.NewPseudonymSystemClient(conn),
		curve:         curve,
	}, nil
}

// GenerateMasterKey generates a master secret key to be used subsequently by all the
// protocols in the scheme.
func (c *PseudonymsysClientEC) GenerateMasterKey() *big.Int {
	group := groups.NewECGroup(c.curve)
	return common.GetRandomInt(group.Q)
}

// GenerateNym generates a nym and registers it to the organization. Do not
// use the same CACertificateEC for different organizations - use it only once!
func (c *PseudonymsysClientEC) GenerateNym(userSecret *big.Int,
	caCertificate *pseudonymsys.CACertificateEC, regKey string) (
	*pseudonymsys.PseudonymEC, error) {
	if err := c.openStream(c.grpcClient, "GenerateNym_EC"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	prover := dlogproofs.NewECDLogEqualityProver(c.curve)

	// Differently as in Pseudonym Systems paper a user here generates a nym (if master
	// key pair is (g, g^s), a generated nym is (g^gamma, g^(gamma * s)),
	// however a user needs to prove that log_nymA(nymB) = log_blindedA(blindedB).

	// Note that as there is very little logic needed (besides what is in DLog equality
	// prover), everything is implemented here (no pseudoynymsys nym gen client).

	masterNymA := groups.NewECGroupElement(prover.Group.Curve.Params().Gx,
		prover.Group.Curve.Params().Gy)
	masterNymB := prover.Group.Exp(masterNymA, userSecret)

	gamma := common.GetRandomInt(prover.Group.Q)
	nymA := prover.Group.Exp(masterNymA, gamma)
	nymB := prover.Group.Exp(masterNymB, gamma)

	// Prove now that log_nymA(nymB) = log_blindedA(blindedB):
	// g1 = nymA, g2 = blindedA
	x1, x2 := prover.GetProofRandomData(userSecret, nymA, caCertificate.BlindedA)
	pRandomData := pb.PseudonymsysNymGenProofRandomDataEC{
		X1:     pb.ToPbECGroupElement(x1),
		A1:     pb.ToPbECGroupElement(nymA),
		B1:     pb.ToPbECGroupElement(nymB),
		X2:     pb.ToPbECGroupElement(x2),
		A2:     pb.ToPbECGroupElement(caCertificate.BlindedA),
		B2:     pb.ToPbECGroupElement(caCertificate.BlindedB),
		R:      caCertificate.R.Bytes(),
		S:      caCertificate.S.Bytes(),
		RegKey: regKey,
	}

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_PseudonymsysNymGenProofRandomDataEc{
			&pRandomData,
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	pedersenDecommitment := resp.GetPedersenDecommitment()
	challenge := new(big.Int).SetBytes(pedersenDecommitment.X)

	z := prover.GetProofData(challenge)

	msg := &pb.Message{
		Content: &pb.Message_SchnorrProofData{
			&pb.SchnorrProofData{
				Z: z.Bytes(),
				//Trapdoor: trapdoor.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}
	verified := resp.GetStatus().Success

	if err := c.genericClient.CloseSend(); err != nil {
		return nil, err
	}

	if verified {
		// todo: store in some DB: (orgName, nymA, nymB)
		return pseudonymsys.NewPseudonymEC(nymA, nymB), nil
	} else {
		err := fmt.Errorf("proof for nym registration failed")
		return nil, err
	}
}

// ObtainCredential returns anonymous credential.
func (c *PseudonymsysClientEC) ObtainCredential(userSecret *big.Int,
	nym *pseudonymsys.PseudonymEC, orgPubKeys *pseudonymsys.PubKeyEC) (
	*pseudonymsys.CredentialEC, error) {
	if err := c.openStream(c.grpcClient, "ObtainCredential_EC"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. Authentication is done via Schnorr.
	schnorrProver, err := dlogproofs.NewSchnorrECProver(c.curve, protocoltypes.Sigma)
	if err != nil {
		return nil, err
	}

	x := schnorrProver.GetProofRandomData(userSecret, nym.A)

	pRandomData := pb.SchnorrECProofRandomData{
		X: pb.ToPbECGroupElement(x),
		A: pb.ToPbECGroupElement(nym.A),
		B: pb.ToPbECGroupElement(nym.B),
	}

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_SchnorrEcProofRandomData{
			&pRandomData,
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	ch := resp.GetBigint()
	challenge := new(big.Int).SetBytes(ch.X1)

	z, _ := schnorrProver.GetProofData(challenge)
	msg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: z.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	randomData := resp.GetPseudonymsysIssueProofRandomDataEc()
	// Now the organization needs to prove that it knows log_b(A), log_g(h2) and log_b(A) = log_g(h2).
	// And to prove that it knows log_aA(B), log_g(h1) and log_aA(B) = log_g(h1).
	// g1 = dlog.G, g2 = nym.B, t1 = A, t2 = orgPubKeys.H2

	x11 := randomData.X11.GetNativeType()
	x12 := randomData.X12.GetNativeType()
	x21 := randomData.X21.GetNativeType()
	x22 := randomData.X22.GetNativeType()
	A := randomData.A.GetNativeType()
	B := randomData.B.GetNativeType()

	gamma := common.GetRandomInt(schnorrProver.Group.Q)
	equalityVerifier1 := dlogproofs.NewECDLogEqualityBTranscriptVerifier(c.curve, gamma)
	equalityVerifier2 := dlogproofs.NewECDLogEqualityBTranscriptVerifier(c.curve, gamma)

	g := groups.NewECGroupElement(equalityVerifier1.Group.Curve.Params().Gx,
		equalityVerifier1.Group.Curve.Params().Gy)

	challenge1 := equalityVerifier1.GetChallenge(g, nym.B, orgPubKeys.H2, A, x11, x12)
	aA := equalityVerifier1.Group.Mul(nym.A, A)
	challenge2 := equalityVerifier2.GetChallenge(g, aA, orgPubKeys.H1, B, x21, x22)

	msg = &pb.Message{
		Content: &pb.Message_DoubleBigint{
			&pb.DoubleBigInt{
				X1: challenge1.Bytes(),
				X2: challenge2.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	proofData := resp.GetDoubleBigint()
	z1 := new(big.Int).SetBytes(proofData.X1)
	z2 := new(big.Int).SetBytes(proofData.X2)

	verified1, transcript1, bToGamma, AToGamma := equalityVerifier1.Verify(z1)
	verified2, transcript2, aAToGamma, BToGamma := equalityVerifier2.Verify(z2)

	aToGamma := equalityVerifier1.Group.Exp(nym.A, gamma)
	if verified1 && verified2 {
		valid1 := dlogproofs.VerifyBlindedTranscriptEC(transcript1, c.curve, g, orgPubKeys.H2,
			bToGamma, AToGamma)
		valid2 := dlogproofs.VerifyBlindedTranscriptEC(transcript2, c.curve, g, orgPubKeys.H1,
			aAToGamma, BToGamma)
		if valid1 && valid2 {
			credential := pseudonymsys.NewCredentialEC(aToGamma, bToGamma, AToGamma, BToGamma,
				transcript1, transcript2)
			return credential, nil
		}
	}

	if err := c.genericClient.CloseSend(); err != nil {
		return nil, err
	}

	err = fmt.Errorf("organization failed to prove that a credential is valid")
	return nil, err
}

// TransferCredential transfers orgName's credential to organization where the
// authentication should happen (the organization takes credential issued by
// another organization).
func (c *PseudonymsysClientEC) TransferCredential(orgName string, userSecret *big.Int,
	nym *pseudonymsys.PseudonymEC, credential *pseudonymsys.CredentialEC) (*pb.SessionKey, error) {
	if err := c.openStream(c.grpcClient, "TransferCredential_EC"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. But we need also to prove that dlog_a(b) = dlog_a2(b2), where
	// a2, b2 are a1, b1 exponentiated to gamma, and (a1, b1) is a nym for organization that
	// issued a credential. So we can do both proofs at the same time using DLogEqualityProver.
	equalityProver := dlogproofs.NewECDLogEqualityProver(c.curve)
	x1, x2 := equalityProver.GetProofRandomData(userSecret, nym.A, credential.SmallAToGamma)

	transcript1 := &pb.PseudonymsysTranscriptEC{
		A: pb.ToPbECGroupElement(groups.NewECGroupElement(credential.T1.Alpha_1,
			credential.T1.Alpha_2)),
		B: pb.ToPbECGroupElement(groups.NewECGroupElement(credential.T1.Beta_1,
			credential.T1.Beta_2)),
		Hash:   credential.T1.Hash.Bytes(),
		ZAlpha: credential.T1.ZAlpha.Bytes(),
	}
	transcript2 := &pb.PseudonymsysTranscriptEC{
		A: pb.ToPbECGroupElement(groups.NewECGroupElement(credential.T2.Alpha_1,
			credential.T2.Alpha_2)),
		B: pb.ToPbECGroupElement(groups.NewECGroupElement(credential.T2.Beta_1,
			credential.T2.Beta_2)),
		Hash:   credential.T2.Hash.Bytes(),
		ZAlpha: credential.T2.ZAlpha.Bytes(),
	}
	pbCredential := &pb.PseudonymsysCredentialEC{
		SmallAToGamma: pb.ToPbECGroupElement(credential.SmallAToGamma),
		SmallBToGamma: pb.ToPbECGroupElement(credential.SmallBToGamma),
		AToGamma:      pb.ToPbECGroupElement(credential.AToGamma),
		BToGamma:      pb.ToPbECGroupElement(credential.BToGamma),
		T1:            transcript1,
		T2:            transcript2,
	}
	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_PseudonymsysTransferCredentialDataEc{
			&pb.PseudonymsysTransferCredentialDataEC{
				OrgName:    orgName,
				X1:         pb.ToPbECGroupElement(x1),
				X2:         pb.ToPbECGroupElement(x2),
				NymA:       pb.ToPbECGroupElement(nym.A),
				NymB:       pb.ToPbECGroupElement(nym.B),
				Credential: pbCredential,
			},
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	ch := resp.GetBigint()
	challenge := new(big.Int).SetBytes(ch.X1)

	z := equalityProver.GetProofData(challenge)
	msg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: z.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	sessionKey := resp.GetSessionKey()
	if sessionKey == nil {
		return nil, fmt.Errorf(resp.GetProtocolError())
	}

	if err := c.genericClient.CloseSend(); err != nil {
		return nil, err
	}

	return sessionKey, nil
}
