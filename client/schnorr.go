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
	"fmt"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"math/big"
)

type SchnorrClient struct {
	genericClient
	prover  *dlogproofs.SchnorrProver
	secret  *big.Int
	a       *big.Int
	variant pb.SchemaVariant
}

// NewSchnorrClient returns an initialized struct of type SchnorrClient.
func NewSchnorrClient(conn *grpc.ClientConn, variant pb.SchemaVariant, dlog *dlog.ZpDLog,
	s *big.Int) (*SchnorrClient, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	return &SchnorrClient{
		genericClient: *genericClient,
		variant:       variant,
		prover:        dlogproofs.NewSchnorrProver(dlog, types.ToProtocolType(variant)),
		secret:        s,
		a:             dlog.G,
	}, nil
}

// Run starts the Schnorr protocol for proving knowledge of a discrete logarithm in multiplicative
// group of integers modulo p. It executes either sigma protocol or Zero Knowledge Proof(of
// knowledge)
func (c *SchnorrClient) Run() error {
	if c.variant == pb.SchemaVariant_SIGMA {
		return c.runSigma()
	}
	return c.runZeroKnowledge()
}

// runSigma runs the sigma version of the Schnorr protocol
func (c *SchnorrClient) runSigma() error {
	c.openStream()
	defer c.closeStream()

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_SCHNORR,
		SchemaVariant: pb.SchemaVariant_SIGMA,
	}
	pedersenDecommitment, err := c.getProofRandomData(true, initMsg)
	if err != nil {
		return err
	}

	challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
	proved, err := c.getProofData(challenge)
	if err != nil {
		return err
	}
	logger.Noticef("Decommitment successful, proved: %v", proved)

	return nil
}

// runZeroKnowledge runs the ZKP or ZKPOK version of Schnorr protocol, depending on the value
// of SchnorrClient's variant field.
func (c *SchnorrClient) runZeroKnowledge() error {
	c.openStream()
	defer c.closeStream()

	commitment, err := c.open() // sends pedersen's h=g^trapdoor
	if err != nil {
		return err
	}
	c.prover.PedersenReceiver.SetCommitment(commitment)

	pedersenDecommitment, err := c.getProofRandomData(false, &pb.Message{})
	if err != nil {
		return err
	}

	challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)

	if success := c.prover.PedersenReceiver.CheckDecommitment(r, challenge); success {
		proved, err := c.getProofData(challenge)
		logger.Noticef("Decommitment successful, proved: %v", proved)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Decommitment failed")
	}

	return nil
}

func (c *SchnorrClient) open() (*big.Int, error) {
	h := c.prover.GetOpeningMsg()
	openMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_SCHNORR,
		SchemaVariant: c.variant,
		Content: &pb.Message_PedersenFirst{
			&pb.PedersenFirst{H: h.Bytes()},
		},
	}

	resp, err := c.getResponseTo(openMsg)
	if err != nil {
		return nil, err
	}
	bigint := resp.GetBigint()
	return new(big.Int).SetBytes(bigint.X1), nil
}

func (c *SchnorrClient) getProofRandomData(isFirstMsg bool, msg *pb.Message) (*pb.PedersenDecommitment, error) {
	x := c.prover.GetProofRandomData(c.secret, c.a)
	b, _ := c.prover.DLog.Exponentiate(c.a, c.secret)
	pRandomData := pb.SchnorrProofRandomData{
		X: x.Bytes(),
		A: c.a.Bytes(),
		B: b.Bytes(),
	}

	msg.Content = &pb.Message_SchnorrProofRandomData{
		&pRandomData,
	}
	resp, err := c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	return resp.GetPedersenDecommitment(), nil
}

func (c *SchnorrClient) getProofData(challenge *big.Int) (bool, error) {
	z, trapdoor := c.prover.GetProofData(challenge)
	if trapdoor == nil { // sigma protocol and ZKP
		trapdoor = new(big.Int)
	}
	msg := &pb.Message{
		Content: &pb.Message_SchnorrProofData{
			&pb.SchnorrProofData{
				Z:        z.Bytes(),
				Trapdoor: trapdoor.Bytes(),
			},
		},
	}

	resp, err := c.getResponseTo(msg)
	if err != nil {
		return false, err
	}
	return resp.GetStatus().Success, nil
}
