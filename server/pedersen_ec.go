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

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/groups"
	pb "github.com/xlab-si/emmy/protobuf"
)

func (s *Server) PedersenEC(curveType groups.ECurve, stream pb.Protocol_RunServer) error {
	pedersenECReceiver := commitments.NewPedersenECReceiver(curveType)

	h := pedersenECReceiver.GetH()
	ecge := pb.ECGroupElement{
		X: h.X.Bytes(),
		Y: h.Y.Bytes(),
	}
	resp := &pb.Message{Content: &pb.Message_EcGroupElement{&ecge}}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	el := req.GetEcGroupElement()
	if el == nil {
		s.logger.Critical("Got a nil EC group element")
		return err
	}

	myEl := el.GetNativeType()
	pedersenECReceiver.SetCommitment(myEl)
	resp = &pb.Message{Content: &pb.Message_Empty{&pb.EmptyMsg{}}}
	if err = s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	pedersenDecommitment := req.GetPedersenDecommitment()
	val := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)
	valid := pedersenECReceiver.CheckDecommitment(r, val)

	s.logger.Noticef("Commitment scheme success: **%v**", valid)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
