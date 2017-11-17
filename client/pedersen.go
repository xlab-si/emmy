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
	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/groups"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
	"math/big"
)

type PedersenClient struct {
	pedersenCommonClient
	committer *commitments.PedersenCommitter
	val       *big.Int
}

// NewPedersenClient returns an initialized struct of type PedersenClient.
func NewPedersenClient(conn *grpc.ClientConn, variant pb.SchemaVariant, dlog *groups.SchnorrGroup,
	val *big.Int) (*PedersenClient, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	validateVariant(variant)

	return &PedersenClient{
		pedersenCommonClient: pedersenCommonClient{genericClient: *genericClient},
		committer:            commitments.NewPedersenCommitter(dlog),
		val:                  val,
	}, nil
}

// Run runs Pedersen commitment protocol in multiplicative group of integers modulo p.
func (c *PedersenClient) Run() error {
	c.openStream()
	defer c.closeStream()

	pf, err := c.getH()
	if err != nil {
		return err
	}

	el := new(big.Int).SetBytes(pf.H)
	c.committer.SetH(el)

	commitment, err := c.committer.GetCommitMsg(c.val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return err
	}

	if err = c.commit(commitment); err != nil {
		return err
	}

	decommitVal, r := c.committer.GetDecommitMsg()
	if err = c.decommit(decommitVal, r); err != nil {
		return err
	}

	return nil
}

func (c *PedersenClient) getH() (*pb.PedersenFirst, error) {
	initMsg := &pb.Message{
		ClientId: c.id,
		Schema:   pb.SchemaType_PEDERSEN,
		Content:  &pb.Message_Empty{&pb.EmptyMsg{}},
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}
	return resp.GetPedersenFirst(), nil
}

func (c *PedersenClient) commit(commitment *big.Int) error {
	commitmentMsg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: commitment.Bytes()},
		},
	}

	if _, err := c.getResponseTo(commitmentMsg); err != nil {
		return err
	}
	return nil
}

func validateVariant(v pb.SchemaVariant) {
	if v != pb.SchemaVariant_SIGMA {
		logger.Warningf("Pedersen protocol supports only SIGMA protocol (requested %v). Running SIGMA instead", v)
	}
}
