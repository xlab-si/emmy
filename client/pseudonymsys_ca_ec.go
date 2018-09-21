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

	"github.com/xlab-si/emmy/crypto/ec"
	"github.com/xlab-si/emmy/crypto/ecpseudsys"
	"github.com/xlab-si/emmy/crypto/ecschnorr"
	pb "github.com/xlab-si/emmy/proto"
	"google.golang.org/grpc"
)

type PseudonymsysCAClientEC struct {
	genericClient
	grpcClient pb.PseudonymSystemCAClient
	curve      ec.Curve
	prover     *ecschnorr.Prover
}

func NewPseudonymsysCAClientEC(conn *grpc.ClientConn, curve ec.Curve) (*PseudonymsysCAClientEC, error) {
	return &PseudonymsysCAClientEC{
		genericClient: newGenericClient(),
		grpcClient:    pb.NewPseudonymSystemCAClient(conn),
		curve:         curve,
		prover:        ecschnorr.NewProver(curve),
	}, nil
}

// GenerateMasterNym generates a master pseudonym to be used with GenerateCertificate.
func (c *PseudonymsysCAClientEC) GenerateMasterNym(secret *big.Int) *ecpseudsys.Nym {
	group := ec.NewGroup(c.curve)
	a := ec.NewGroupElement(group.Curve.Params().Gx, group.Curve.Params().Gy)
	b := group.Exp(a, secret)
	return ecpseudsys.NewNym(a, b)
}

// GenerateCertificate provides a certificate from trusted CA to the user. Note that CA
// needs to know the user. The certificate is then used for registering pseudonym (nym).
// The certificate contains blinded user's master key pair and a signature of it.
func (c *PseudonymsysCAClientEC) GenerateCertificate(userSecret *big.Int, nym *ecpseudsys.Nym) (
	*ecpseudsys.CACert, error) {
	if err := c.openStream(c.grpcClient, "GenerateCertificate_EC"); err != nil {
		return nil, err
	}
	defer c.closeStream()

	x := c.prover.GetProofRandomData(userSecret, nym.A)
	pRandomData := pb.SchnorrECProofRandomData{
		X: pb.ToPbECGroupElement(x),
		A: pb.ToPbECGroupElement(nym.A),
		B: pb.ToPbECGroupElement(nym.B),
	}

	initMsg := &pb.Message{
		ClientId: c.id,
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

	z := c.prover.GetProofData(challenge)
	msg := &pb.Message{
		Content: &pb.Message_SchnorrProofData{
			&pb.SchnorrProofData{
				Z: z.Bytes(),
			},
		},
	}

	resp, err = c.getResponseTo(msg)
	if err != nil {
		return nil, err
	}

	cert := resp.GetPseudonymsysCaCertificateEc()
	certificate := ecpseudsys.NewCACert(
		cert.BlindedA.GetNativeType(),
		cert.BlindedB.GetNativeType(),
		new(big.Int).SetBytes(cert.R), new(big.Int).SetBytes(cert.S))

	if err := c.genericClient.CloseSend(); err != nil {
		return nil, err
	}

	return certificate, nil
}
