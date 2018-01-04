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
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
)

func (s *Server) PseudonymsysCAEC(curveType groups.ECurve, req *pb.Message,
	stream pb.Protocol_RunServer) error {
	var err error

	d := config.LoadPseudonymsysCASecret()
	pubKeyX, pubKeyY := config.LoadPseudonymsysCAPubKey()
	ca := pseudonymsys.NewCAEC(d, pubKeyX, pubKeyY, curveType)

	sProofRandData := req.GetSchnorrEcProofRandomData()
	x := types.ToECGroupElement(sProofRandData.X)
	a := types.ToECGroupElement(sProofRandData.A)
	b := types.ToECGroupElement(sProofRandData.B)

	challenge := ca.GetChallenge(a, b, x)
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

	sProofData := req.GetSchnorrProofData()
	z := new(big.Int).SetBytes(sProofData.Z)
	cert, err := ca.Verify(z)

	if err == nil {
		resp = &pb.Message{
			Content: &pb.Message_PseudonymsysCaCertificateEc{
				&pb.PseudonymsysCACertificateEC{
					BlindedA: types.ToPbECGroupElement(cert.BlindedA),
					BlindedB: types.ToPbECGroupElement(cert.BlindedB),
					R:        cert.R.Bytes(),
					S:        cert.S.Bytes(),
				},
			},
		}
	} else {
		resp = &pb.Message{
			Content: &pb.Message_PseudonymsysCaCertificateEc{
				&pb.PseudonymsysCACertificateEC{},
			},
			ProtocolError: err.Error(),
		}
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
