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

	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/protocoltypes"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
)

type PseudonymsysCAClient struct {
	genericClient
	grpcClient pb.PseudonymSystemCAClient
	prover     *dlogproofs.SchnorrProver
}

func NewPseudonymsysCAClient(conn *grpc.ClientConn) (*PseudonymsysCAClient, error) {
	group := config.LoadGroup("pseudonymsys")

	return &PseudonymsysCAClient{
		genericClient: newGenericClient(),
		grpcClient:    pb.NewPseudonymSystemCAClient(conn),
		prover:        dlogproofs.NewSchnorrProver(group, protocoltypes.Sigma),
	}, nil
}

// GenerateCertificate provides a certificate from trusted CA to the user. Note that CA
// needs to know the user. The certificate is then used for registering pseudonym (nym).
// The certificate contains blinded user's master key pair and a signature of it.
func (c *PseudonymsysCAClient) GenerateCertificate(userSecret *big.Int, nym *pseudonymsys.Pseudonym) (
	*pseudonymsys.CACertificate, error) {

	if err := c.openStream(c.grpcClient, "GenerateCertificate"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	x := c.prover.GetProofRandomData(userSecret, nym.A)
	b := c.prover.Group.Exp(nym.A, userSecret)
	pRandomData := pb.SchnorrProofRandomData{
		X: x.Bytes(),
		A: nym.A.Bytes(),
		B: b.Bytes(),
	}

	initMsg := &pb.Message{
		ClientId: c.id,
		Content: &pb.Message_SchnorrProofRandomData{
			&pRandomData,
		},
	}
	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}

	ch := resp.GetBigint()
	challenge := new(big.Int).SetBytes(ch.X1)

	z, _ := c.prover.GetProofData(challenge)
	trapdoor := new(big.Int)
	msg := &pb.Message{
		Content: &pb.Message_SchnorrProofData{
			&pb.SchnorrProofData{
				Z:        z.Bytes(),
				Trapdoor: trapdoor.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}
	cert := resp.GetPseudonymsysCaCertificate()
	certificate := pseudonymsys.NewCACertificate(
		new(big.Int).SetBytes(cert.BlindedA), new(big.Int).SetBytes(cert.BlindedB),
		new(big.Int).SetBytes(cert.R), new(big.Int).SetBytes(cert.S))

	return certificate, nil
}
