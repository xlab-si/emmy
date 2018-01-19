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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/protobuf"
)

func (s *Server) PseudonymsysGenerateNymEC(curveType groups.ECurve, req *pb.Message,
	stream pb.Protocol_RunServer) error {
	caPubKeyX, caPubKeyY := config.LoadPseudonymsysCAPubKey()
	org := pseudonymsys.NewOrgNymGenEC(caPubKeyX, caPubKeyY, curveType)

	proofRandData := req.GetPseudonymsysNymGenProofRandomDataEc()
	x1 := proofRandData.X1.GetNativeType()
	nymA := proofRandData.A1.GetNativeType()
	nymB := proofRandData.B1.GetNativeType()
	x2 := proofRandData.X2.GetNativeType()
	blindedA := proofRandData.A2.GetNativeType()
	blindedB := proofRandData.B2.GetNativeType()
	signatureR := new(big.Int).SetBytes(proofRandData.R)
	signatureS := new(big.Int).SetBytes(proofRandData.S)

	regKeyOk, err := s.registrationManager.CheckRegistrationKey(proofRandData.RegKey)

	var resp *pb.Message

	if !regKeyOk || err != nil {
		s.logger.Errorf("Registration key %s ok=%t, error=%v",
			proofRandData.RegKey, regKeyOk, err)
		resp = &pb.Message{
			ProtocolError: "registration key verification failed",
		}

		if err = s.send(resp, stream); err != nil {
			return err
		}
	} else {
		challenge, err := org.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2, signatureR, signatureS)
		if err != nil {
			s.logger.Error(err)
			resp = &pb.Message{
				ProtocolError: err.Error(),
			}
		} else {
			resp = &pb.Message{
				Content: &pb.Message_PedersenDecommitment{
					&pb.PedersenDecommitment{
						X: challenge.Bytes(),
					},
				},
			}
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
	}

	return nil
}

func (s *Server) PseudonymsysIssueCredentialEC(curveType groups.ECurve, req *pb.Message,
	stream pb.Protocol_RunServer) error {
	proofRandData := req.GetSchnorrEcProofRandomData()
	x := proofRandData.X.GetNativeType()
	a := proofRandData.A.GetNativeType()
	b := proofRandData.B.GetNativeType()

	s1, s2 := config.LoadPseudonymsysOrgSecrets("org1", "ecdlog")
	org := pseudonymsys.NewOrgCredentialIssuerEC(s1, s2, curveType)
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

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	proofData := req.GetBigint()
	z := new(big.Int).SetBytes(proofData.X1)

	x11, x12, x21, x22, A, B, err := org.VerifyAuthentication(z)

	if err != nil {
		s.logger.Error(err)
		resp = &pb.Message{
			ProtocolError: err.Error(),
		}
	} else {
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

func (s *Server) PseudonymsysTransferCredentialEC(curveType groups.ECurve, req *pb.Message,
	stream pb.Protocol_RunServer) error {
	s1, s2 := config.LoadPseudonymsysOrgSecrets("org1", "ecdlog")
	org := pseudonymsys.NewOrgCredentialVerifierEC(s1, s2, curveType)

	data := req.GetPseudonymsysTransferCredentialDataEc()
	orgName := data.OrgName
	x1 := data.X1.GetNativeType()
	x2 := data.X2.GetNativeType()
	nymA := data.NymA.GetNativeType()
	nymB := data.NymB.GetNativeType()

	t1 := dlogproofs.NewTranscriptEC(
		new(big.Int).SetBytes(data.Credential.T1.A.X),
		new(big.Int).SetBytes(data.Credential.T1.A.Y),
		new(big.Int).SetBytes(data.Credential.T1.B.X),
		new(big.Int).SetBytes(data.Credential.T1.B.Y),
		new(big.Int).SetBytes(data.Credential.T1.Hash),
		new(big.Int).SetBytes(data.Credential.T1.ZAlpha))

	t2 := dlogproofs.NewTranscriptEC(
		new(big.Int).SetBytes(data.Credential.T2.A.X),
		new(big.Int).SetBytes(data.Credential.T2.A.Y),
		new(big.Int).SetBytes(data.Credential.T2.B.X),
		new(big.Int).SetBytes(data.Credential.T2.B.Y),
		new(big.Int).SetBytes(data.Credential.T2.Hash),
		new(big.Int).SetBytes(data.Credential.T2.ZAlpha))

	credential := pseudonymsys.NewCredentialEC(
		data.Credential.SmallAToGamma.GetNativeType(),
		data.Credential.SmallBToGamma.GetNativeType(),
		data.Credential.AToGamma.GetNativeType(),
		data.Credential.BToGamma.GetNativeType(),
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

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	// PubKeys of the organization that issue a credential:
	h1X, h1Y, h2X, h2Y := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	h1 := groups.NewECGroupElement(h1X, h1Y)
	h2 := groups.NewECGroupElement(h2X, h2Y)
	orgPubKeys := pseudonymsys.NewOrgPubKeysEC(h1, h2)

	proofData := req.GetBigint()
	z := new(big.Int).SetBytes(proofData.X1)

	verified := org.VerifyAuthentication(z, credential, orgPubKeys)

	resp = &pb.Message{}
	// If something went wrong (either user was not authenticated or secure session key could not
	// be generated), then sessionKey will be nil and the message will contain ProtocolError.
	if verified {
		sessionKey, err := s.generateSessionKey()
		if err != nil {
			s.logger.Error(err)
			resp.ProtocolError = "failed to obtain session key"
		} else {
			resp.Content = &pb.Message_SessionKey{
				SessionKey: &pb.SessionKey{
					Value: *sessionKey,
				},
			}
		}
	} else {
		s.logger.Error("User authentication failed")
		resp.ProtocolError = "user authentication failed"
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
