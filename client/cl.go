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
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
	/*
	"fmt"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	*/
	"fmt"
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
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: big.NewInt(2).Bytes(),
			},
		},
	}

	resp, err := c.getResponseTo(initMsg)
	fmt.Println("__-----------------------------__________________________--------------")
	if err != nil {
		return nil, err
	}

	fmt.Println("------------------")
	fmt.Println(resp)

	return nil, nil
}


