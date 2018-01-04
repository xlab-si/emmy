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

	"github.com/xlab-si/emmy/crypto/encryption"
	pb "github.com/xlab-si/emmy/protobuf"
)

func (s *Server) CSPaillier(req *pb.Message, secKeyPath string, stream pb.Protocol_RunServer) error {
	decryptor, err := encryption.NewCSPaillierFromSecKey(secKeyPath)
	if err != nil {
		return err
	}

	opening := req.GetCsPaillierOpening()

	u := new(big.Int).SetBytes(opening.U)
	e := new(big.Int).SetBytes(opening.E)
	v := new(big.Int).SetBytes(opening.V)
	delta := new(big.Int).SetBytes(opening.Delta)
	label := new(big.Int).SetBytes(opening.Label)
	l := new(big.Int).SetBytes(opening.L)

	decryptor.SetVerifierEncData(u, e, v, delta, label, l)

	resp := &pb.Message{
		Content: &pb.Message_Empty{&pb.EmptyMsg{}},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	pRandData := req.GetCsPaillierProofRandomData()

	u1 := new(big.Int).SetBytes(pRandData.U1)
	e1 := new(big.Int).SetBytes(pRandData.E1)
	v1 := new(big.Int).SetBytes(pRandData.V1)
	delta1 := new(big.Int).SetBytes(pRandData.Delta1)
	l1 := new(big.Int).SetBytes(pRandData.L1)

	c := decryptor.GetChallenge()
	decryptor.SetProofRandomData(u1, e1, v1, delta1, l1, c)

	challenge := pb.BigInt{
		X1: c.Bytes(),
	}
	resp = &pb.Message{
		Content: &pb.Message_Bigint{&challenge},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	pData := req.GetCsPaillierProofData()

	rTilde := new(big.Int).SetBytes(pData.RTilde)
	if pData.RTildeIsNeg {
		rTilde = new(big.Int).Neg(rTilde)
	}

	sTilde := new(big.Int).SetBytes(pData.STilde)
	if pData.STildeIsNeg {
		sTilde = new(big.Int).Neg(sTilde)
	}

	mTilde := new(big.Int).SetBytes(pData.MTilde)
	if pData.MTildeIsNeg {
		mTilde = new(big.Int).Neg(mTilde)
	}

	isOk := decryptor.Verify(rTilde, sTilde, mTilde)
	status := pb.Status{
		Success: isOk,
	}

	resp = &pb.Message{
		Content: &pb.Message_Status{&status},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
