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
	"github.com/xlab-si/emmy/crypto/ecpseudsys"
	"github.com/xlab-si/emmy/crypto/ecschnorr"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GenerateNym_EC(stream pb.PseudonymSystem_GenerateNym_ECServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	caPubKey := config.LoadPseudonymsysCAPubKey()
	org := ecpseudsys.NewNymGenerator(caPubKey, curve)

	proofRandData := req.GetPseudonymsysNymGenProofRandomDataEc()
	x1 := proofRandData.X1.GetNativeType()
	nymA := proofRandData.A1.GetNativeType()
	nymB := proofRandData.B1.GetNativeType()
	x2 := proofRandData.X2.GetNativeType()
	blindedA := proofRandData.A2.GetNativeType()
	blindedB := proofRandData.B2.GetNativeType()
	signatureR := new(big.Int).SetBytes(proofRandData.R)
	signatureS := new(big.Int).SetBytes(proofRandData.S)

	regKeyOk, err := s.RegistrationManager.CheckRegistrationKey(proofRandData.RegKey)

	var resp *pb.Message

	if !regKeyOk || err != nil {
		s.Logger.Debugf("Registration key %s ok=%t, error=%v",
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

func (s *Server) ObtainCredential_EC(stream pb.PseudonymSystem_ObtainCredential_ECServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	proofRandData := req.GetSchnorrEcProofRandomData()
	x := proofRandData.X.GetNativeType()
	a := proofRandData.A.GetNativeType()
	b := proofRandData.B.GetNativeType()

	secKey := config.LoadPseudonymsysOrgSecrets("org1", "ecdlog")
	org := ecpseudsys.NewCredIssuer(secKey, curve)
	challenge := org.GetChallenge(a, b, x)

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

	x11, x12, x21, x22, A, B, err := org.Verify(z)

	if err != nil {
		s.Logger.Debug(err)
		return status.Error(codes.Internal, err.Error())
	}
	resp = &pb.Message{
		Content: &pb.Message_PseudonymsysIssueProofRandomDataEc{
			&pb.PseudonymsysIssueProofRandomDataEC{
				X11: pb.ToPbECGroupElement(x11),
				X12: pb.ToPbECGroupElement(x12),
				X21: pb.ToPbECGroupElement(x21),
				X22: pb.ToPbECGroupElement(x22),
				A:   pb.ToPbECGroupElement(A),
				B:   pb.ToPbECGroupElement(B),
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

	z1, z2 := org.GetProofData(challenge1, challenge2)
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

func (s *Server) TransferCredential_EC(stream pb.PseudonymSystem_TransferCredential_ECServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	secKey := config.LoadPseudonymsysOrgSecrets("org1", "ecdlog")
	org := ecpseudsys.NewCredVerifier(secKey, curve)

	data := req.GetPseudonymsysTransferCredentialDataEc()
	orgName := data.OrgName
	x1 := data.X1.GetNativeType()
	x2 := data.X2.GetNativeType()
	nymA := data.NymA.GetNativeType()
	nymB := data.NymB.GetNativeType()

	t1 := ecschnorr.NewBlindedTrans(
		new(big.Int).SetBytes(data.Credential.T1.A.X),
		new(big.Int).SetBytes(data.Credential.T1.A.Y),
		new(big.Int).SetBytes(data.Credential.T1.B.X),
		new(big.Int).SetBytes(data.Credential.T1.B.Y),
		new(big.Int).SetBytes(data.Credential.T1.Hash),
		new(big.Int).SetBytes(data.Credential.T1.ZAlpha))

	t2 := ecschnorr.NewBlindedTrans(
		new(big.Int).SetBytes(data.Credential.T2.A.X),
		new(big.Int).SetBytes(data.Credential.T2.A.Y),
		new(big.Int).SetBytes(data.Credential.T2.B.X),
		new(big.Int).SetBytes(data.Credential.T2.B.Y),
		new(big.Int).SetBytes(data.Credential.T2.Hash),
		new(big.Int).SetBytes(data.Credential.T2.ZAlpha))

	credential := ecpseudsys.NewCred(
		data.Credential.SmallAToGamma.GetNativeType(),
		data.Credential.SmallBToGamma.GetNativeType(),
		data.Credential.AToGamma.GetNativeType(),
		data.Credential.BToGamma.GetNativeType(),
		t1, t2,
	)

	challenge := org.GetChallenge(nymA, nymB,
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
	orgPubKeys := config.LoadPseudonymsysOrgPubKeysEC(orgName)

	proofData := req.GetBigint()
	z := new(big.Int).SetBytes(proofData.X1)

	if verified := org.Verify(z, credential, orgPubKeys); !verified {
		s.Logger.Debug("User authentication failed")
		return status.Error(codes.Unauthenticated, "user authentication failed")
	}

	sessionKey, err := s.GenerateSessionKey()
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
