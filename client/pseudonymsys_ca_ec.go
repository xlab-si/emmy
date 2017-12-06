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
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"math/big"
)

type PseudonymsysCAClientEC struct {
	genericClient
	prover *dlogproofs.SchnorrECProver
}

func NewPseudonymsysCAClientEC(conn *grpc.ClientConn, curve groups.ECurve) (*PseudonymsysCAClientEC, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	prover, err := dlogproofs.NewSchnorrECProver(curve, types.Sigma)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAClientEC{
		genericClient: *genericClient,
		prover:        prover,
	}, nil
}

// ObtainCertificate provides a certificate from trusted CA to the user. Note that CA
// needs to know the user. The certificate is then used for registering pseudonym (nym).
// The certificate contains blinded user's master key pair and a signature of it.
func (c *PseudonymsysCAClientEC) ObtainCertificate(userSecret *big.Int, nym *pseudonymsys.PseudonymEC) (
	*pseudonymsys.CACertificateEC, error) {
	c.openStream()
	defer c.closeStream()

	x := c.prover.GetProofRandomData(userSecret, nym.A)
	pRandomData := pb.SchnorrECProofRandomData{
		X: types.ToPbECGroupElement(x),
		A: types.ToPbECGroupElement(nym.A),
		B: types.ToPbECGroupElement(nym.B),
	}

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_PSEUDONYMSYS_CA_EC,
		SchemaVariant: pb.SchemaVariant_SIGMA,
		Content: &pb.Message_SchnorrEcProofRandomData{
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

	cert := resp.GetPseudonymsysCaCertificateEc()
	certificate := pseudonymsys.NewCACertificateEC(
		types.ToECGroupElement(cert.BlindedA),
		types.ToECGroupElement(cert.BlindedB),
		new(big.Int).SetBytes(cert.R), new(big.Int).SetBytes(cert.S))

	if err := c.stream.CloseSend(); err != nil {
		return nil, err
	}

	return certificate, nil
}
