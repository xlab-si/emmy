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
	"github.com/xlab-si/emmy/crypto/zkp/protocoltypes"
	pb "github.com/xlab-si/emmy/protobuf"
)

func (s *Server) SchnorrEC(req *pb.Message, protocolType protocoltypes.ProtocolType,
	stream pb.Protocol_RunServer, curve groups.ECurve) error {
	verifier := dlogproofs.NewSchnorrECVerifier(curve, protocolType)
	var err error

	if protocolType != protocoltypes.Sigma {
		// ZKP, ZKPOK
		ecge := req.GetEcGroupElement()
		h := ecge.GetNativeType()
		commitment := verifier.GetOpeningMsgReply(h)
		pb_ecge := pb.ToPbECGroupElement(commitment)

		resp := &pb.Message{
			Content: &pb.Message_EcGroupElement{
				pb_ecge,
			},
		}

		if err := s.send(resp, stream); err != nil {
			return err
		}

		req, err = s.receive(stream)
		if err != nil {
			return err
		}
	}

	sProofRandData := req.GetSchnorrEcProofRandomData()

	x := sProofRandData.X.GetNativeType()
	a := sProofRandData.A.GetNativeType()
	b := sProofRandData.B.GetNativeType()
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
