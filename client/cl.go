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
	"math/big"

	"github.com/xlab-si/emmy/crypto/cl"
	"github.com/xlab-si/emmy/crypto/common"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
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

func (c *CLClient) IssueCredential(credManager *cl.CredManager) (*cl.Cred, error) {
	if err := c.openStream(c.grpcClient, "IssueCredential"); err != nil {
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

	credIssueNonceOrg := new(big.Int).SetBytes(resp.GetBigint().X1)

	credReq, err := credManager.GetCredRequest(credIssueNonceOrg)
	if err != nil {
		return nil, err
	}

	credReqMsg := &pb.Message{
		Content: &pb.Message_CLCredReq{pb.ToPbCredentialRequest(credReq)},
	}
	resp, err = c.getResponseTo(credReqMsg)
	if err != nil {
		return nil, err
	}

	pbCred := resp.GetCLCredential()
	credential, AProof, err := pbCred.GetNativeType()
	if err != nil {
		return nil, err
	}

	userVerified, err := credManager.VerifyCred(credential, AProof)
	if err != nil {
		return nil, err
	}

	if userVerified {
		return credential, nil
	}

	return nil, fmt.Errorf("credential not valid")
}

func (c *CLClient) UpdateCredential(credManager *cl.CredManager, newKnownAttrs []*big.Int) (*cl.Cred,
	error) {
	credManager.UpdateCred(newKnownAttrs)

	if err := c.openStream(c.grpcClient, "UpdateCredential"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_UpdateClCredential{
			pb.ToPbUpdateCLCredential(credManager.Nym, credManager.CredReqNonce, newKnownAttrs),
		},
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	pbCred := resp.GetCLCredential()
	credential, AProof, err := pbCred.GetNativeType()
	if err != nil {
		return nil, err
	}

	userVerified, err := credManager.VerifyCred(credential, AProof)
	if err != nil {
		return nil, err
	}

	if userVerified {
		return credential, nil
	}

	return nil, fmt.Errorf("credential not valid")
}

// ProveCred proves the possession of a valid credential and reveals only the attributes the user desires
// to reveal. Which knownAttrs and commitmentsOfAttrs are to be revealed are given by revealedKnownAttrsIndices and
// revealedCommitmentsOfAttrsIndices parameters. All knownAttrs and commitmentsOfAttrs should be passed into
// ProveCred - only those which are revealed are then passed to the server.
func (c *CLClient) ProveCredential(credManager *cl.CredManager, cred *cl.Cred,
	knownAttrs []*big.Int, revealedKnownAttrsIndices, revealedCommitmentsOfAttrsIndices []int) (bool, error) {
	if err := c.openStream(c.grpcClient, "ProveCredential"); err != nil {
		return false, err
	}
	defer c.closeStream()

	initMsg := &pb.Message{
		ClientId: c.id,
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return false, err
	}

	nonce := new(big.Int).SetBytes(resp.GetBigint().X1)

	randCred, proof, err := credManager.BuildCredProof(cred, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, nonce)
	if err != nil {
		return false, fmt.Errorf("error when building credential proof: %v", err)
	}

	filteredKnownAttrs := []*big.Int{}
	for i := 0; i < len(knownAttrs); i++ {
		if common.Contains(revealedKnownAttrsIndices, i) {
			filteredKnownAttrs = append(filteredKnownAttrs, knownAttrs[i])
		}
	}
	filteredCommitmentsOfAttrs := []*big.Int{}
	for i := 0; i < len(credManager.CommitmentsOfAttrs); i++ {
		if common.Contains(revealedCommitmentsOfAttrsIndices, i) {
			filteredCommitmentsOfAttrs = append(filteredCommitmentsOfAttrs, credManager.CommitmentsOfAttrs[i])
		}
	}

	proveMsg := &pb.Message{
		Content: &pb.Message_ProveClCredential{pb.ToPbProveCLCredential(randCred.A, proof, filteredKnownAttrs,
			filteredCommitmentsOfAttrs, revealedKnownAttrsIndices, revealedCommitmentsOfAttrsIndices)},
	}
	resp, err = c.getResponseTo(proveMsg)
	if err != nil {
		return false, err
	}

	return resp.GetStatus().Success, nil
}
