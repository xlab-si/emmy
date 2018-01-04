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

	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
)

func (s *Server) Schnorr(req *pb.Message, group *groups.SchnorrGroup,
	protocolType types.ProtocolType, stream pb.Protocol_RunServer) error {
	verifier := dlogproofs.NewSchnorrVerifier(group, protocolType)
	var err error

	if protocolType != types.Sigma {
		// ZKP, ZKPOK
		pedersenFirst := req.GetPedersenFirst()
		h := new(big.Int).SetBytes(pedersenFirst.H)
		commitment := verifier.GetOpeningMsgReply(h)

		resp := &pb.Message{
			Content: &pb.Message_Bigint{
				&pb.BigInt{X1: commitment.Bytes()},
			},
		}

		if err = s.send(resp, stream); err != nil {
			return err
		}

		req, err = s.receive(stream)
		if err != nil {
			return err
		}
	}

	sProofRandData := req.GetSchnorrProofRandomData()

	x := new(big.Int).SetBytes(sProofRandData.X)
	a := new(big.Int).SetBytes(sProofRandData.A)
	b := new(big.Int).SetBytes(sProofRandData.B)
	verifier.SetProofRandomData(x, a, b)

	challenge, r2 := verifier.GetChallenge() // r2 is nil in sigma protocol
	if r2 == nil {
		r2 = new(big.Int)
	}

	// pb.PedersenDecommitment is used also for SigmaProtocol (where there is no r2)
	resp := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{
			&pb.PedersenDecommitment{
				X: challenge.Bytes(),
				R: r2.Bytes(),
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

	sProofData := req.GetSchnorrProofData()
	z := new(big.Int).SetBytes(sProofData.Z)
	trapdoor := new(big.Int).SetBytes(sProofData.Trapdoor)
	valid := verifier.Verify(z, trapdoor)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
