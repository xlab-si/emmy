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
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/qrproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
	"math/big"
)

type QRClient struct {
	genericClient
	prover  *qrproofs.QRProver
	variant pb.SchemaVariant
}

// NewQRClient returns an initialized struct of type QRClient.
func NewQRClient(conn *grpc.ClientConn, dlog *dlog.ZpDLog, y1 *big.Int) (*QRClient, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	return &QRClient{
		genericClient: *genericClient,
		prover:        qrproofs.NewQRProver(dlog, y1),
	}, nil
}

// Run starts protocol for proving knowledge of a square root.
func (c *QRClient) Run() (bool, error) {
	c.openStream()
	defer c.closeStream()

	// proof requires as many rounds as is the bit length of modulo N
	m := c.prover.DLog.P.BitLen()

	// message where y is sent to the verifier - this message could be as well skipped and
	// y could be sent via the first message in a loop
	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_QR,
		SchemaVariant: pb.SchemaVariant_SIGMA,
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: c.prover.Y.Bytes()},
		},
	}
	_, err := c.getResponseTo(initMsg) // simply an empty message
	if err != nil {
		return false, err
	}

	proved := false
	// the client has to prove for all i - if in one iteration the knowledge
	// is not proved, the protocol is stopped
	for i := 0; i < m; i++ {
		c.sendProofRandomData()
		challenge, err := c.getChallenge()
		if err != nil {
			return false, err
		}

		proved, err = c.sendProofData(challenge)
		if err != nil {
			return false, err
		}
		if !proved {
			break
		}
	}

	return proved, nil
}

func (c *QRClient) sendProofRandomData() error {
	x := c.prover.GetProofRandomData()
	msg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: x.Bytes()},
		},
	}
	err := c.send(msg)
	return err
}

func (c *QRClient) getChallenge() (*big.Int, error) {
	resp, err := c.receive()
	if err != nil {
		return nil, err
	}
	challenge := new(big.Int).SetBytes(resp.GetBigint().X1)
	return challenge, nil
}

func (c *QRClient) sendProofData(challenge *big.Int) (bool, error) {
	proofData, err := c.prover.GetProofData(challenge)
	if err != nil {
		return false, err
	}
	msg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: proofData.Bytes()},
		},
	}

	resp, err := c.getResponseTo(msg)
	if err != nil {
		return false, err
	}
	proved := resp.GetStatus().Success
	return proved, nil
}
