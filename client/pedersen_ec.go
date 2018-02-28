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

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/groups"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
)

type PedersenECClient struct {
	pedersenCommonClient
	committer *commitments.PedersenECCommitter
	val       *big.Int
}

// NewPedersenECClient returns an initialized struct of type PedersenECClient.
func NewPedersenECClient(conn *grpc.ClientConn, v *big.Int, curveType groups.ECurve) (*PedersenECClient, error) {
	return &PedersenECClient{
		pedersenCommonClient: pedersenCommonClient{
			genericClient: newGenericClient(),
			grpcClient:    pb.NewProtocolClient(conn),
		},
		committer: commitments.NewPedersenECCommitter(curveType),
		val:       v,
	}, nil
}

// Run runs Pedersen commitment protocol in the eliptic curve group.
func (c *PedersenECClient) Run() error {
	if err := c.openStream(c.grpcClient, "Run"); err != nil {
		return err
	}
	defer c.closeStream()

	h, err := c.getH()
	if err != nil {
		return err
	}
	myH := h.GetNativeType()
	c.committer.SetH(myH)

	commitment, err := c.committer.GetCommitMsg(c.val)
	if err != nil {
		logger.Criticalf("could not generate commitment message: %v", err)
		return nil
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

func (c *PedersenECClient) getH() (*pb.ECGroupElement, error) {
	initMsg := &pb.Message{
		ClientId: c.id,
		Schema:   pb.SchemaType_PEDERSEN_EC,
		Content:  &pb.Message_Empty{&pb.EmptyMsg{}},
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}
	return resp.GetEcGroupElement(), nil
}

func (c *PedersenECClient) commit(commitVal *groups.ECGroupElement) error {
	commitmentMsg := &pb.Message{
		Content: &pb.Message_EcGroupElement{
			pb.ToPbECGroupElement(commitVal),
		},
	}

	if _, err := c.getResponseTo(commitmentMsg); err != nil {
		return err
	}
	return nil
}
