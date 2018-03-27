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

package server

import (
	"math/big"

	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GenerateNym(stream pb.PseudonymSystem_GenerateNymServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	group := config.LoadSchnorrGroup()
	caPubKey := config.LoadPseudonymsysCAPubKey()
	org := pseudonymsys.NewOrgNymGen(group, caPubKey)

	proofRandData := req.GetPseudonymsysNymGenProofRandomData()
	x1 := new(big.Int).SetBytes(proofRandData.X1)
	nymA := new(big.Int).SetBytes(proofRandData.A1)
	nymB := new(big.Int).SetBytes(proofRandData.B1)
	x2 := new(big.Int).SetBytes(proofRandData.X2)
	blindedA := new(big.Int).SetBytes(proofRandData.A2)
	blindedB := new(big.Int).SetBytes(proofRandData.B2)
	signatureR := new(big.Int).SetBytes(proofRandData.R)
	signatureS := new(big.Int).SetBytes(proofRandData.S)

	regKeyOk, err := s.RegistrationManager.CheckRegistrationKey(proofRandData.RegKey)

	var resp *pb.Message

	if !regKeyOk || err != nil {
		s.Logger.Debugf("registration key %s ok=%t, error=%v",
			proofRandData.RegKey, regKeyOk, err)
		return status.Error(codes.NotFound, "registration key verification failed")
	}

	challenge, err := org.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2, signatureR, signatureS)
	if err != nil {
		s.Logger.Debug(err)
		return status.Error(codes.Internal, err.Error())

	}
	resp = &pb.Message{
		Content: &pb.Message_PedersenDecommitment{
			&pb.PedersenDecommitment{
				X: challenge.Bytes(),
			},
		},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	proofData := req.GetSchnorrProofData() // SchnorrProofData is used in DLog equality proof as well
	z := new(big.Int).SetBytes(proofData.Z)
	valid := org.Verify(z)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}

func (s *Server) ObtainCredential(stream pb.PseudonymSystem_ObtainCredentialServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	group := config.LoadSchnorrGroup()
	secKey := config.LoadPseudonymsysOrgSecrets("org1", "dlog")
	org := pseudonymsys.NewOrgCredentialIssuer(group, secKey)

	sProofRandData := req.GetSchnorrProofRandomData()
	x := new(big.Int).SetBytes(sProofRandData.X)
	a := new(big.Int).SetBytes(sProofRandData.A)
	b := new(big.Int).SetBytes(sProofRandData.B)
	challenge := org.GetAuthenticationChallenge(a, b, x)

	resp := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: challenge.Bytes(),
			},
		},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	proofData := req.GetBigint()
	z := new(big.Int).SetBytes(proofData.X1)

	x11, x12, x21, x22, A, B, err := org.VerifyAuthentication(z)
	if err != nil {
		s.Logger.Debug(err)
		return status.Error(codes.Internal, err.Error())
	}
	resp = &pb.Message{
		Content: &pb.Message_PseudonymsysIssueProofRandomData{
			&pb.PseudonymsysIssueProofRandomData{
				X11: x11.Bytes(),
				X12: x12.Bytes(),
				X21: x21.Bytes(),
				X22: x22.Bytes(),
				A:   A.Bytes(),
				B:   B.Bytes(),
			},
		},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	challenges := req.GetDoubleBigint()
	challenge1 := new(big.Int).SetBytes(challenges.X1)
	challenge2 := new(big.Int).SetBytes(challenges.X2)

	z1, z2 := org.GetEqualityProofData(challenge1, challenge2)
	resp = &pb.Message{
		Content: &pb.Message_DoubleBigint{
			&pb.DoubleBigInt{
				X1: z1.Bytes(),
				X2: z2.Bytes(),
			},
		},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	return nil
}

func (s *Server) TransferCredential(stream pb.PseudonymSystem_TransferCredentialServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	group := config.LoadSchnorrGroup()
	secKey := config.LoadPseudonymsysOrgSecrets("org1", "dlog")
	org := pseudonymsys.NewOrgCredentialVerifier(group, secKey)

	data := req.GetPseudonymsysTransferCredentialData()
	orgName := data.OrgName
	x1 := new(big.Int).SetBytes(data.X1)
	x2 := new(big.Int).SetBytes(data.X2)
	nymA := new(big.Int).SetBytes(data.NymA)
	nymB := new(big.Int).SetBytes(data.NymB)

	t1 := dlogproofs.NewTranscript(
		new(big.Int).SetBytes(data.Credential.T1.A),
		new(big.Int).SetBytes(data.Credential.T1.B),
		new(big.Int).SetBytes(data.Credential.T1.Hash),
		new(big.Int).SetBytes(data.Credential.T1.ZAlpha),
	)

	t2 := dlogproofs.NewTranscript(
		new(big.Int).SetBytes(data.Credential.T2.A),
		new(big.Int).SetBytes(data.Credential.T2.B),
		new(big.Int).SetBytes(data.Credential.T2.Hash),
		new(big.Int).SetBytes(data.Credential.T2.ZAlpha),
	)

	credential := pseudonymsys.NewCredential(
		new(big.Int).SetBytes(data.Credential.SmallAToGamma),
		new(big.Int).SetBytes(data.Credential.SmallBToGamma),
		new(big.Int).SetBytes(data.Credential.AToGamma),
		new(big.Int).SetBytes(data.Credential.BToGamma),
		t1, t2,
	)

	challenge := org.GetAuthenticationChallenge(nymA, nymB,
		credential.SmallAToGamma, credential.SmallBToGamma, x1, x2)

	resp := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: challenge.Bytes(),
			},
		},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	// PubKeys of the organization that issue a credential:
	orgPubKeys := config.LoadPseudonymsysOrgPubKeys(orgName)

	proofData := req.GetBigint()
	z := new(big.Int).SetBytes(proofData.X1)

	if verified := org.VerifyAuthentication(z, credential, orgPubKeys); !verified {
		s.Logger.Debug("User authentication failed")
		return status.Error(codes.Unauthenticated, "user authentication failed")
	}

	sessionKey, err := s.generateSessionKey()
	if err != nil {
		s.Logger.Debug(err)
		return status.Error(codes.Internal, "failed to obtain session key")
	}

	resp = &pb.Message{
		Content: &pb.Message_SessionKey{
			SessionKey: &pb.SessionKey{
				Value: *sessionKey,
			},
		},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
