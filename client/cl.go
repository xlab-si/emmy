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

func (c *CLClient) GetCredentialStructure() (*cl.RawCred, error) {
	cred, err := c.grpcClient.GetCredentialStructure(context.Background(), &empty.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve credential structure info: %v", err)
	}

	/*
		attributes := cred.GetAttributes()
		rawCred := cl.NewRawCred()
		for _, a := range attributes {
			// attributes need to be properly indexed to enable preparation of lists of
			// their values which are sent to the verifier (and need to be ordered by index)
			rawCred.InsertAttribute(int(a.GetIndex()), a.GetName(), a.GetType(), a.GetKnown())
		}

		return rawCred, nil
	*/
	count := cl.NewAttrCount(
		int(cred.NKnown),
		int(cred.NCommitted),
		int(cred.NHidden),
	)
	rc := cl.NewRawCred(count)

	attrs := cred.Attributes
	for _, a := range attrs {
		switch u := a.Type.(type) { // TODO make more intuitive
		case *pb.CredAttribute_StringAttr:
			fmt.Println("Client received string attribute", u.StringAttr)
			strA := a.GetStringAttr().Attr
			err := rc.AddEmptyStrAttr(strA.Name, strA.Known)
			if err != nil {
				return nil, err
			}
		case *pb.CredAttribute_IntAttr:
			fmt.Println("Client received int attribute", u.IntAttr)
			intA := a.GetIntAttr().Attr
			err := rc.AddEmptyInt64Attr(intA.Name, intA.Known)
			if err != nil {
				return nil, err
			}
		}
	}

	return rc, nil
}

func (c *CLClient) GetAcceptableCreds() (map[string][]string, error) {
	creds, err := c.grpcClient.GetAcceptableCredentials(context.Background(), &empty.Empty{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve acceptable credentials info: %v", err)
	}

	accCreds := make(map[string][]string)
	for _, cred := range creds.Creds {
		var attrs []string
		for _, attr := range cred.GetRevealedAttrs() {
			attrs = append(attrs, attr)
		}
		accCreds[cred.GetOrgName()] = attrs
	}
	return accCreds, nil
}

/*
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
		Content: &pb.Message_CLCredReq{pb.ToPbCredRequest(credReq)},
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

	userVerified, err := credManager.Verify(credential, AProof)
	if err != nil {
		return nil, err
	}

	if userVerified {
		return credential, nil
	}

	return nil, fmt.Errorf("credential not valid")
}

func (c *CLClient) UpdateCredential(credManager *cl.CredManager, rawCred *cl.RawCred) (*cl.Cred,
	error) {
	// refresh credManager with new credential values, works only for known attributes
	credManager.Update(rawCred)
	newKnownAttrs := rawCred.GetKnownValues()

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

	userVerified, err := credManager.Verify(credential, AProof)
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
	revealedAttrIndices []string) (string, error) {
	var revealedKnownAttrsIndices []int
	var revealedCommitmentsOfAttrsIndices []int
	knownCount := 0
	commCount := 0
	attributes := credManager.RawCred.GetAttrs()
	for i := 0; i < len(attributes); i++ { // not using range to force attributes appear in proper order
		attr := attributes[i]
		if common.Contains(revealedAttrIndices, attr.Index) {
			if attr.Known {
				revealedKnownAttrsIndices = append(revealedKnownAttrsIndices, knownCount)
			} else {
				revealedCommitmentsOfAttrsIndices = append(revealedCommitmentsOfAttrsIndices, commCount)
			}
		}
		if attr.Known {
			knownCount++
		} else {
			commCount++
		}
	}

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

	randCred, proof, err := credManager.BuildProof(cred, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, nonce)
	if err != nil {
		return false, fmt.Errorf("error when building credential proof: %v", err)
	}

	filteredKnownAttrs, filteredCommitmentsOfAttrs := credManager.FilterAttributes(revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices)

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
*/
