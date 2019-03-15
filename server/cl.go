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
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/cl"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetCredentialStructure(ctx context.Context, _ *empty.Empty) (*pb.CredStructure, error) {
	s.Logger.Info("Client requested credential structure information")
	/*
		attrs, err := config.LoadCredentialStructure()
		if err != nil {
			return nil, err
		}

		attributes := make([]*pb.Attribute, len(attrs))
		for i, a := range attrs {
			attributes[i] = &pb.Attribute{
				Index: int32(a.Index),
				Name:  a.Name,
				Type:  a.Type,
				Known: a.Known,
			}
		}
		cred := &pb.CredentialStructure{
			Attributes: attributes,
		}

		return cred, nil
	*/
	structure, err := config.LoadCredentialStructure()
	if err != nil {
		return nil, err
	}

	attrs, attrCount, err := cl.ParseAttrs(structure)
	credAttrs := make([]*pb.CredAttribute, len(attrs))

	for i, a := range attrs {
		attr := &pb.Attribute{
			Name:  a.GetName(),
			Known: a.IsKnown(),
		}
		switch a.(type) {
		case *cl.StrAttr:
			credAttrs[i] = &pb.CredAttribute{
				Type: &pb.CredAttribute_StringAttr{
					StringAttr: &pb.StringAttribute{
						Attr: attr,
					},
				},
			}
		case *cl.Int64Attr:
			credAttrs[i] = &pb.CredAttribute{
				Type: &pb.CredAttribute_IntAttr{
					IntAttr: &pb.IntAttribute{
						Attr: attr,
					},
				},
			}
		}
	}

	return &pb.CredStructure{
		NKnown:     int32(attrCount.Known),
		NCommitted: int32(attrCount.Committed),
		NHidden:    int32(attrCount.Hidden),
		Attributes: credAttrs,
	}, nil
}

func (s *Server) GetAcceptableCredentials(ctx context.Context, _ *empty.Empty) (*pb.AcceptableCreds, error) {
	s.Logger.Info("Client requested acceptable credentials information")
	accCreds, err := config.LoadAcceptableCredentials()
	if err != nil {
		return nil, err
	}

	var credentials []*pb.AcceptableCred
	for name, attrs := range accCreds {
		cred := &pb.AcceptableCred{
			OrgName:       name,
			RevealedAttrs: attrs,
		}
		credentials = append(credentials, cred)
	}

	return &pb.AcceptableCreds{
		Creds: credentials,
	}, nil
}

func (s *Server) IssueCredential(stream pb.CL_IssueCredentialServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	initReq := req.GetRegKey()
	regKeyOk, err := s.RegistrationManager.CheckRegistrationKey(initReq.RegKey)
	if !regKeyOk || err != nil {
		s.Logger.Debugf("registration key %s ok=%t, error=%v",
			initReq.RegKey, regKeyOk, err)
		return status.Error(codes.NotFound, "registration key verification failed")
	}

	org, err := cl.LoadOrg("../client/testdata/clPubKey.gob", "../client/testdata/clSecKey.gob")
	if err != nil {
		return err
	}

	nonce := org.GetCredIssueNonce()
	resp := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: nonce.Bytes(),
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

	cReq := req.GetCLCredReq()
	credReq, err := cReq.GetNativeType()
	if err != nil {
		return err
	}

	// Issue the credential
	res, err := org.IssueCred(credReq)
	if err != nil {
		return fmt.Errorf("error when issuing credential: %v", err)
	}
	// Store the newly obtained receiver record to the database
	if err = s.clRecordManager.Store(credReq.Nym, res.Record); err != nil {
		return err
	}

	pbCred := pb.ToPbCLCredential(res.Cred, res.AProof)
	resp = &pb.Message{
		Content: &pb.Message_CLCredential{pbCred},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	return nil
}

func (s *Server) UpdateCredential(stream pb.CL_UpdateCredentialServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	org, err := cl.LoadOrg("../client/testdata/clPubKey.gob", "../client/testdata/clSecKey.gob")
	if err != nil {
		return err
	}

	u := req.GetUpdateClCredential()
	nym, nonce, newKnownAttrs := u.GetNativeType()

	// Retrieve the receiver record from the database
	rec, err := s.clRecordManager.Load(nym)
	if err != nil {
		return err
	}
	// Do credential update
	res, err := org.UpdateCred(nym, rec, nonce, newKnownAttrs)
	if err != nil {
		return fmt.Errorf("error when updating credential: %v", err)
	}
	// Store the updated receiver record to the database
	if err = s.clRecordManager.Store(nym, res.Record); err != nil {
		return err
	}

	pbCred := pb.ToPbCLCredential(res.Cred, res.AProof)
	resp := &pb.Message{
		Content: &pb.Message_CLCredential{pbCred},
	}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	return nil
}

func (s *Server) ProveCredential(stream pb.CL_ProveCredentialServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	org, err := cl.LoadOrg("../client/testdata/clPubKey.gob", "../client/testdata/clSecKey.gob")
	if err != nil {
		return err
	}

	nonce := org.GetProveCredNonce()
	resp := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: nonce.Bytes(),
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

	pReq := req.GetProveClCredential()
	A, proof, knownAttrs, commitmentsOfAttrs, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, err := pReq.GetNativeType()
	if err != nil {
		return err
	}

	verified, err := org.ProveCred(A, proof, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, knownAttrs, commitmentsOfAttrs)
	if err != nil {
		s.Logger.Debug(err)
		return status.Error(codes.Internal, "error when proving credential")
	}

	if !verified {
		s.Logger.Debug("User authentication failed")
		return status.Error(codes.Unauthenticated, "user authentication failed")
	}

	sessionKey, err := s.GenerateSessionKey()
	if err != nil {
		s.Logger.Debug(err)
		return status.Error(codes.Internal, "failed to obtain session key")
	}

	// TODO: here session key needs to be stored to enable validation

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
