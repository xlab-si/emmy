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
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
	"math/big"
	/*
		"fmt"

		"github.com/xlab-si/emmy/crypto/common"
		"github.com/xlab-si/emmy/crypto/groups"
		"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
		"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	*/
	"fmt"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/qrspecialrsaproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/cl"
	"github.com/xlab-si/emmy/proto"
)

type CLClient struct {
	genericClient
	grpcClient pb.CLClient
}

func NewCLClient(conn *grpc.ClientConn) (*CLClient, error) {
	return &CLClient{
		genericClient: newGenericClient(),
		grpcClient:    pb.NewCLClient(conn),
	}, nil
}

func (c *CLClient) GetCredentialIssueNonce() (*big.Int, error) {
	if err := c.openStream(c.grpcClient, "GetCredentialIssueNonce"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	initMsg := &pb.Message{
		ClientId: c.id,
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	nonce := new(big.Int).SetBytes(resp.GetBigint().X1)
	fmt.Println(nonce)

	return nonce, nil
}

func (c *CLClient) IssueCredential(credReq *cl.CredentialRequest) (*cl.Credential,
	*qrspecialrsaproofs.RepresentationProof, error) {
	if err := c.openStream(c.grpcClient, "IssueCredential"); err != nil {
		return nil, nil, err
	}
	defer c.closeStream()

	cReq := proto.ToPbCredentialRequest(credReq)

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_CLCredReq{cReq},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println("response:")
	fmt.Println(resp)



	return nil, nil, nil
}
