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
	"context"
	"fmt"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/xlab-si/emmy/crypto/cl"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
)

func GetCredentialStructure(conn *grpc.ClientConn) (*cl.RawCredential, error) {
	client := pb.NewCLCredentialInfoClient(conn)

	cred, err := client.GetCredentialStructure(context.Background(), &empty.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve credential structure info: %v", err)
	}

	attributes := cred.GetAttributes()
	attrs := make([]cl.Attribute, len(attributes))
	for i, a := range attributes {
		attr := cl.NewAttribute(int(a.GetIndex()), a.GetName(), a.GetType(), a.GetKnown(), nil)
		attrs[i] = *attr
	}
	rawCred := cl.NewRawCredential(attrs)

	return rawCred, nil
}

func GetAcceptableCredentials(conn *grpc.ClientConn) (map[string][]int, error) {
	client := pb.NewCLCredentialInfoClient(conn)

	creds, err := client.GetAcceptableCredentials(context.Background(), &empty.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve acceptable credentials info: %v", err)
	}

	accCreds := make(map[string][]int)
	for _, cred := range creds.Credentials {
		var indices []int
		for attr := range cred.GetRevealedAttrs() {
			indices = append(indices, int(attr))
		}
		accCreds[cred.GetOrgName()] = indices
	}
	return accCreds, nil
}
