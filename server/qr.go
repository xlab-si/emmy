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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

func (s *Server) QR(req *pb.Message, group *groups.SchnorrGroup,
	stream pb.Protocol_RunServer) error {

	initMsg := req.GetBigint()
	y := new(big.Int).SetBytes(initMsg.X1)
	verifier := qrproofs.NewQRVerifier(y, group)
	var err error

	resp := &pb.Message{
		Content: &pb.Message_Empty{&pb.EmptyMsg{}},
	}
	if err := s.send(resp, stream); err != nil {
		return err
	}

	m := group.P.BitLen()
	// the client has to prove for all i - if in one iteration the knowledge
	// is not proved, the protocol is stopped
	for i := 0; i < m; i++ {
		req, err = s.receive(stream)
		if err != nil {
			return err
		}
		proofRandomData := new(big.Int).SetBytes(req.GetBigint().X1)
		challenge := verifier.GetChallenge(proofRandomData)

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
		proved := verifier.Verify(z)

		resp = &pb.Message{
			Content: &pb.Message_Status{&pb.Status{Success: proved}},
		}

		if err = s.send(resp, stream); err != nil {
			return err
		}

		if !proved {
			break
		}
	}

	return nil
}
