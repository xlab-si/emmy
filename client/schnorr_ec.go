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
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"math/big"
)

type SchnorrECClient struct {
	genericClient
	prover  *dlogproofs.SchnorrECProver
	secret  *big.Int
	a       *types.ECGroupElement
	variant pb.SchemaVariant
}

// NewSchnorrECClient returns an initialized struct of type SchnorrECClient.
func NewSchnorrECClient(conn *grpc.ClientConn, variant pb.SchemaVariant, curve dlog.Curve,
	s *big.Int) (*SchnorrECClient, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	prover, err := dlogproofs.NewSchnorrECProver(curve, types.ToProtocolType(variant))
	if err != nil {
		return nil, fmt.Errorf("Could not create schnorr EC prover: %v", err)
	}

	return &SchnorrECClient{
		genericClient: *genericClient,
		prover:        prover,
		variant:       variant,
		secret:        s,
		a: &types.ECGroupElement{
			X: prover.DLog.Curve.Params().Gx,
			Y: prover.DLog.Curve.Params().Gy,
		},
	}, nil
}

// Run starts the Schnorr protocol for proving knowledge of a discrete logarithm in elliptic curve
// group. It executes either sigma protocol or Zero Knowledge Proof (of knowledge)
func (c *SchnorrECClient) Run() error {
	if c.variant == pb.SchemaVariant_SIGMA {
		return c.runSigma()
	}
	return c.runZeroKnowledge()
}

// RunSigma runs the sigma version of the Schnorr protocol in the elliptic curve group
func (c *SchnorrECClient) runSigma() error {
	c.openStream()
	defer c.closeStream()

	pedersenDecommitment, err := c.getProofRandomData(true)
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

// runZeroKnowledge runs the ZKP or ZKPOK version of Schnorr protocol in the elliptic curve group,
// depending on the value of SchnorrClient's variant field.
func (c *SchnorrECClient) runZeroKnowledge() error {
	c.openStream()
	defer c.closeStream()

	commitment, err := c.open()
	if err != nil {
		return err
	}

	c.prover.PedersenReceiver.SetCommitment(commitment)
	pedersenDecommitment, err := c.getProofRandomData(false)
	if err != nil {
		return err
	}

	challenge := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)

	success := c.prover.PedersenReceiver.CheckDecommitment(r, challenge)
	if success {
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

func (c *SchnorrECClient) open() (*types.ECGroupElement, error) {
	h := c.prover.GetOpeningMsg()
	ecge := types.ToPbECGroupElement(h)
	openMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_SCHNORR_EC,
		SchemaVariant: c.variant,
		Content:       &pb.Message_EcGroupElement{ecge},
	}

	resp, err := c.getResponseTo(openMsg)
	if err != nil {
		return nil, err
	}

	ecge = resp.GetEcGroupElement()
	return types.ToECGroupElement(ecge), nil
}

func (c *SchnorrECClient) getProofRandomData(isFirstMsg bool) (*pb.PedersenDecommitment, error) {
	x := c.prover.GetProofRandomData(c.secret, c.a) // x = a^r, b = a^secret is "public key"
	b1, b2 := c.prover.DLog.Exponentiate(c.a.X, c.a.Y, c.secret)
	b := &types.ECGroupElement{X: b1, Y: b2}

	pRandomData := pb.SchnorrECProofRandomData{
		X: types.ToPbECGroupElement(x),
		A: types.ToPbECGroupElement(c.a),
		B: types.ToPbECGroupElement(b),
	}

	req := &pb.Message{}
	if isFirstMsg {
		req = &pb.Message{
			ClientId:      c.id,
			Schema:        pb.SchemaType_SCHNORR_EC,
			SchemaVariant: c.variant,
		}
	}
	req.Content = &pb.Message_SchnorrEcProofRandomData{
		&pRandomData,
	}

	resp, err := c.getResponseTo(req)
	if err != nil {
		return nil, err
	}

	return resp.GetPedersenDecommitment(), nil
}

func (c *SchnorrECClient) getProofData(challenge *big.Int) (bool, error) {
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
