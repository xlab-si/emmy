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

package client

import (
	"math/big"

	"github.com/xlab-si/emmy/crypto/encryption"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
)

type CSPaillierClient struct {
	genericClient
	grpcClient pb.ProtocolClient
	encryptor  *encryption.CSPaillier
	label, m   *big.Int
}

// NewCSPaillierClient returns an initialized struct of type CSPaillierClient.
func NewCSPaillierClient(conn *grpc.ClientConn, pubKeyPath string, m, l *big.Int) (*CSPaillierClient, error) {
	encryptor, err := encryption.NewCSPaillierFromPubKeyFile(pubKeyPath)
	if err != nil {
		return nil, err
	}

	return &CSPaillierClient{
		genericClient: newGenericClient(),
		grpcClient:    pb.NewProtocolClient(conn),
		encryptor:     encryptor,
		m:             m,
		label:         l,
	}, nil
}

// Run runs the Camenisch-Shoup sigma protocol for verifiable encryption and decryption
// of discrete logatirhms.
func (c *CSPaillierClient) Run() error {
	if err := c.openStream(c.grpcClient, "Run"); err != nil {
		return err
	}
	defer c.closeStream()

	u, e, v, _ := c.encryptor.Encrypt(c.m, c.label)
	if err := c.open(u, e, v); err != nil {
		return err
	}

	challenge, err := c.getProofRandomData(u, e)
	if err != nil {
		return err
	}

	_, err = c.getProofData(challenge)
	if err != nil {
		return err
	}

	return nil
}

func (c *CSPaillierClient) open(u, e, v *big.Int) error {
	l, delta := c.encryptor.GetOpeningMsg(c.m)

	opening := pb.CSPaillierOpening{
		U:     u.Bytes(),
		E:     e.Bytes(),
		V:     v.Bytes(),
		Delta: delta.Bytes(),
		Label: c.label.Bytes(),
		L:     l.Bytes(),
	}
	openMsg := &pb.Message{
		ClientId: c.id,
		Schema:   pb.SchemaType_CSPAILLIER,
		Content:  &pb.Message_CsPaillierOpening{&opening},
	}

	if _, err := c.getResponseTo(openMsg); err != nil {
		return err
	}

	return nil
}

func (c *CSPaillierClient) getProofRandomData(u, e *big.Int) (*big.Int, error) {
	u1, e1, v1, delta1, l1, err := c.encryptor.GetProofRandomData(u, e, c.label)
	if err != nil {
		return nil, err
	}

	data := pb.CSPaillierProofRandomData{
		U1:     u1.Bytes(),
		E1:     e1.Bytes(),
		V1:     v1.Bytes(),
		Delta1: delta1.Bytes(),
		L1:     l1.Bytes(),
	}
	msg := &pb.Message{
		Content: &pb.Message_CsPaillierProofRandomData{&data},
	}

	resp, err := c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	bigint := resp.GetBigint()
	return new(big.Int).SetBytes(bigint.X1), nil
}

func (c *CSPaillierClient) getProofData(challenge *big.Int) (bool, error) {
	rTilde, sTilde, mTilde := c.encryptor.GetProofData(challenge)

	data := pb.CSPaillierProofData{
		RTilde:      rTilde.Bytes(),
		RTildeIsNeg: rTilde.Cmp(big.NewInt(0)) < 0,
		STilde:      sTilde.Bytes(),
		STildeIsNeg: sTilde.Cmp(big.NewInt(0)) < 0,
		MTilde:      mTilde.Bytes(),
		MTildeIsNeg: mTilde.Cmp(big.NewInt(0)) < 0,
	}
	msg := &pb.Message{
		Content: &pb.Message_CsPaillierProofData{&data},
	}

	resp, err := c.getResponseTo(msg)
	if err != nil {
		return false, err
	}
	status := resp.GetStatus()
	return status.Success, nil
}
