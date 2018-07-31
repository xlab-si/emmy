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
	//"math/big"

	pb "github.com/xlab-si/emmy/proto"
	/*
		"github.com/xlab-si/emmy/config"
		"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
		"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
		"google.golang.org/grpc/codes"
		"google.golang.org/grpc/status"
	*/
	"fmt"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
)

func (s *Server) IssueCredential(stream pb.CL_IssueCredentialServer) error {
	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	org, err := cl.LoadOrg("organization1", "../client/testdata/clSecKey.gob", "../client/testdata/clPubKey.gob")
	if err != nil {
		return err
	}

	nonce := org.GetCredentialIssueNonce()
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

	credential, AProof, err := org.IssueCredential(credReq)
	if err != nil {
		return fmt.Errorf("error when issuing credential: %v", err)
	}


	fmt.Println("===================")
	fmt.Println(credential)
	fmt.Println(AProof)



	return nil
}
