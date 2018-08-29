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
	"github.com/xlab-si/emmy/crypto/schnorr"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
)

type PseudonymsysClient struct {
	genericClient
	grpcClient pb.PseudonymSystemClient
	group      *schnorr.Group
}

func NewPseudonymsysClient(conn *grpc.ClientConn,
	group *schnorr.Group) (*PseudonymsysClient, error) {
	return &PseudonymsysClient{
		group:         group,
		genericClient: newGenericClient(),
		grpcClient:    pb.NewPseudonymSystemClient(conn),
	}, nil
}

// GenerateMasterKey generates a master secret key, representing a random integer betweeen
// 0 and order of the group. This key will be used subsequently by all the protocols in the scheme.
func (c *PseudonymsysClient) GenerateMasterKey() *big.Int {
	return common.GetRandomInt(c.group.Q)
}

// GenerateNym generates a nym and registers it to the organization. Do not use
// the same CACertificate for different organizations - use it only once!
func (c *PseudonymsysClient) GenerateNym(userSecret *big.Int,
	caCertificate *pseudonymsys.CACertificate, regKey string) (
	*pseudonymsys.Pseudonym, error) {
	if err := c.openStream(c.grpcClient, "GenerateNym"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	prover := dlogproofs.NewDLogEqualityProver(c.group)

	// Differently as in Pseudonym Systems paper a user here generates a nym (if master
	// key pair is (g, g^s), a generated nym is (g^gamma, g^(gamma * s)),
	// however a user needs to prove that log_nymA(nymB) = log_blindedA(blindedB).

	// Note that as there is very little logic needed (besides what is in DLog equality
	// prover), everything is implemented here (no pseudoynymsys nym gen client).
	gamma := common.GetRandomInt(prover.Group.Q)
	nymA := c.group.Exp(c.group.G, gamma)
	nymB := c.group.Exp(nymA, userSecret)

	// Prove now that log_nymA(nymB) = log_blindedA(blindedB):
	// g1 = nymA, g2 = blindedA
	x1, x2 := prover.GetProofRandomData(userSecret, nymA, caCertificate.BlindedA)
	pRandomData := pb.PseudonymsysNymGenProofRandomData{
		X1:     x1.Bytes(),
		A1:     nymA.Bytes(),
		B1:     nymB.Bytes(),
		X2:     x2.Bytes(),
		A2:     caCertificate.BlindedA.Bytes(),
		B2:     caCertificate.BlindedB.Bytes(),
		R:      caCertificate.R.Bytes(),
		S:      caCertificate.S.Bytes(),
		RegKey: regKey,
	}

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_PseudonymsysNymGenProofRandomData{
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
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}
	verified := resp.GetStatus().Success
	if verified {
		// todo: store in some DB: (orgName, nymA, nymB)
		return pseudonymsys.NewPseudonym(nymA, nymB), nil
	} else {
		err := fmt.Errorf("proof for nym registration failed")
		return nil, err
	}
}

// ObtainCredential returns anonymous credential.
func (c *PseudonymsysClient) ObtainCredential(userSecret *big.Int,
	nym *pseudonymsys.Pseudonym, orgPubKeys *pseudonymsys.PubKey) (
	*pseudonymsys.Credential, error) {
	if err := c.openStream(c.grpcClient, "ObtainCredential"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	gamma := common.GetRandomInt(c.group.Q)
	equalityVerifier1 := dlogproofs.NewDLogEqualityBTranscriptVerifier(c.group, gamma)
	equalityVerifier2 := dlogproofs.NewDLogEqualityBTranscriptVerifier(c.group, gamma)

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. Authentication is done via Schnorr.
	schnorrProver, err := schnorr.NewProver(c.group, []*big.Int{userSecret}, []*big.Int{nym.A}, nym.B)
	if err != nil {
		return nil, err
	}
	x := schnorrProver.GetProofRandomData()

	pRandomData := pb.SchnorrProofRandomData{
		X: x.Bytes(),
		A: nym.A.Bytes(),
		B: nym.B.Bytes(),
	}

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_SchnorrProofRandomData{
			&pRandomData,
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	ch := resp.GetBigint()
	challenge := new(big.Int).SetBytes(ch.X1)

	z := schnorrProver.GetProofData(challenge)[0]
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

	randomData := resp.GetPseudonymsysIssueProofRandomData()
	// Now the organization needs to prove that it knows log_b(A), log_g(h2) and log_b(A) = log_g(h2).
	// And to prove that it knows log_aA(B), log_g(h1) and log_aA(B) = log_g(h1).
	// g1 = dlog.G, g2 = nym.B, t1 = A, t2 = orgPubKeys.H2

	x11 := new(big.Int).SetBytes(randomData.X11)
	x12 := new(big.Int).SetBytes(randomData.X12)
	x21 := new(big.Int).SetBytes(randomData.X21)
	x22 := new(big.Int).SetBytes(randomData.X22)
	A := new(big.Int).SetBytes(randomData.A)
	B := new(big.Int).SetBytes(randomData.B)

	challenge1 := equalityVerifier1.GetChallenge(c.group.G, nym.B, orgPubKeys.H2, A, x11, x12)
	aA := c.group.Mul(nym.A, A)
	challenge2 := equalityVerifier2.GetChallenge(c.group.G, aA, orgPubKeys.H1, B, x21, x22)

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

	aToGamma := c.group.Exp(nym.A, gamma)
	if verified1 && verified2 {
		valid1 := dlogproofs.VerifyBlindedTranscript(transcript1, c.group, c.group.G, orgPubKeys.H2,
			bToGamma, AToGamma)
		valid2 := dlogproofs.VerifyBlindedTranscript(transcript2, c.group, c.group.G, orgPubKeys.H1,
			aAToGamma, BToGamma)
		if valid1 && valid2 {
			credential := pseudonymsys.NewCredential(aToGamma, bToGamma, AToGamma, BToGamma,
				transcript1, transcript2)
			return credential, nil
		}
	}

	err = fmt.Errorf("organization failed to prove that a credential is valid")
	return nil, err
}

// TransferCredential transfers orgName's credential to organization where the
// authentication should happen (the organization takes credential issued by
// another organization).
func (c *PseudonymsysClient) TransferCredential(orgName string, userSecret *big.Int,
	nym *pseudonymsys.Pseudonym, credential *pseudonymsys.Credential) (*pb.SessionKey, error) {
	if err := c.openStream(c.grpcClient, "TransferCredential"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. But we need also to prove that dlog_a(b) = dlog_a2(b2), where
	// a2, b2 are a1, b1 exponentiated to gamma, and (a1, b1) is a nym for organization that
	// issued a credential. So we can do both proofs at the same time using DLogEqualityProver.
	equalityProver := dlogproofs.NewDLogEqualityProver(c.group)
	x1, x2 := equalityProver.GetProofRandomData(userSecret, nym.A, credential.SmallAToGamma)

	transcript1 := &pb.PseudonymsysTranscript{
		A:      credential.T1.A.Bytes(),
		B:      credential.T1.B.Bytes(),
		Hash:   credential.T1.Hash.Bytes(),
		ZAlpha: credential.T1.ZAlpha.Bytes(),
	}
	transcript2 := &pb.PseudonymsysTranscript{
		A:      credential.T2.A.Bytes(),
		B:      credential.T2.B.Bytes(),
		Hash:   credential.T2.Hash.Bytes(),
		ZAlpha: credential.T2.ZAlpha.Bytes(),
	}
	pbCredential := &pb.PseudonymsysCredential{
		SmallAToGamma: credential.SmallAToGamma.Bytes(),
		SmallBToGamma: credential.SmallBToGamma.Bytes(),
		AToGamma:      credential.AToGamma.Bytes(),
		BToGamma:      credential.BToGamma.Bytes(),
		T1:            transcript1,
		T2:            transcript2,
	}
	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_PseudonymsysTransferCredentialData{
			&pb.PseudonymsysTransferCredentialData{
				OrgName:    orgName,
				X1:         x1.Bytes(),
				X2:         x2.Bytes(),
				NymA:       nym.A.Bytes(),
				NymB:       nym.B.Bytes(),
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

	if err := c.genericClient.CloseSend(); err != nil {
		return nil, err
	}

	return resp.GetSessionKey(), nil
}
