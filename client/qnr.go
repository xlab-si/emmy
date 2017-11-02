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
	"errors"
	"fmt"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"math/big"
)

type QNRClient struct {
	genericClient
	prover  *qrproofs.QNRProver
	variant pb.SchemaVariant
}

func NewQNRClient(conn *grpc.ClientConn, qr *dlog.QR, y *big.Int) (*QNRClient, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	return &QNRClient{
		genericClient: *genericClient,
		prover:        qrproofs.NewQNRProver(qr, y),
	}, nil
}

// Run starts protocol for proving that y is QNR.
func (c *QNRClient) Run() (bool, error) {
	c.openStream()
	defer c.closeStream()

	// proof requires as many rounds as is the bit length of modulo N
	m := c.prover.QR.N.BitLen()

	// message where y is sent to the verifier
	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_QNR,
		SchemaVariant: pb.SchemaVariant_SIGMA,
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: c.prover.Y.Bytes()},
		},
	}

	resp, err := c.getResponseTo(initMsg) // simply an empty message
	if err != nil {
		return false, err
	}
	if resp.GetEmpty() == nil {
		return false, fmt.Errorf("should receive empty message")
	}

	proved := false
	// the client has to prove for all i - if in one iteration the knowledge
	// is not proved, the protocol is stopped
	for i := 0; i < m; i++ {
		w, pairs, err := c.getVerifierChallenge()
		if err != nil {
			return false, err
		}

		c.prover.SetProofRandomData(w)
		err = c.sendProverChallenge()
		if err != nil {
			return false, err
		}

		verProofPairs, err := c.getVerifierProof()
		if err != nil {
			return false, err
		}

		verifierIsHonest := c.prover.Verify(pairs, verProofPairs)
		if !verifierIsHonest {
			err := errors.New("verifier is not honest")
			return false, err
		}

		typ, err := c.prover.GetProofData(w)
		if err != nil {
			return false, nil
		}

		proved, err = c.sendProof(typ)
		if err != nil {
			return false, nil
		}

		if !proved {
			return false, nil
		}
	}

	return proved, nil
}

func (c *QNRClient) getVerifierChallenge() (*big.Int, []*types.Pair, error) {
	msg := &pb.Message{
		Content: &pb.Message_Empty{&pb.EmptyMsg{}},
	}
	resp, err := c.getResponseTo(msg) // send empty message to start an iteration of a loop
	if err != nil {
		return nil, nil, err
	}

	ch := resp.GetQnrVerifierChallenge()
	w := new(big.Int).SetBytes(ch.W)
	var pairs []*types.Pair
	for _, p := range ch.Pairs {
		pair := types.ToPair(p)
		pairs = append(pairs, pair)
	}
	return w, pairs, nil
}

func (c *QNRClient) sendProverChallenge() error {
	// get challenge from prover for proving that verifier is not cheating
	randVector := c.prover.GetChallenge()
	var ints []int32
	for _, i := range randVector {
		ints = append(ints, int32(i))
	}

	msg := &pb.Message{
		Content: &pb.Message_RepeatedInt{
			&pb.RepeatedInt{Ints: ints},
		},
	}
	if err := c.send(msg); err != nil {
		return err
	}
	return nil
}

func (c *QNRClient) getVerifierProof() ([]*types.Pair, error) {
	resp, err := c.receive()
	if err != nil {
		return nil, err
	}

	verProof := resp.GetRepeatedPair()
	var verProofPairs []*types.Pair
	for _, p := range verProof.Pairs {
		pair := types.ToPair(p)
		verProofPairs = append(verProofPairs, pair)
	}
	return verProofPairs, nil
}

func (c *QNRClient) sendProof(typ int) (bool, error) {
	msg := &pb.Message{
		Content: &pb.Message_Eint{
			int32(typ),
		},
	}

	resp, err := c.getResponseTo(msg)
	if err != nil {
		return false, err
	}
	proved := resp.GetStatus().Success
	return proved, nil
}
