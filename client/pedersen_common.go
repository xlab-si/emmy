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

	pb "github.com/xlab-si/emmy/protobuf"
)

type pedersenCommonClient struct {
	genericClient
	grpcClient pb.ProtocolClient
}

func (c *pedersenCommonClient) decommit(decommitVal, r *big.Int) error {
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{
			&pb.PedersenDecommitment{
				X: decommitVal.Bytes(),
				R: r.Bytes(),
			},
		},
	}

	if _, err := c.getResponseTo(decommitMsg); err != nil {
		return err
	}
	return nil
}
