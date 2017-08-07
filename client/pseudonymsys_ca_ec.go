package client

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/pseudonymsys"
	"google.golang.org/grpc"
	"math/big"
)

type PseudonymsysCAClientEC struct {
	genericClient
	prover *dlogproofs.SchnorrECProver
}

func NewPseudonymsysCAClientEC(conn *grpc.ClientConn) (*PseudonymsysCAClientEC, error) {
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	prover, err := dlogproofs.NewSchnorrECProver(dlog.P256, common.Sigma)
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
	x := c.prover.GetProofRandomData(userSecret, nym.A)
	pRandomData := pb.SchnorrECProofRandomData{
		X: common.ToPbECGroupElement(x),
		A: common.ToPbECGroupElement(nym.A),
		B: common.ToPbECGroupElement(nym.B),
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
		common.ToECGroupElement(cert.BlindedA),
		common.ToECGroupElement(cert.BlindedB),
		new(big.Int).SetBytes(cert.R), new(big.Int).SetBytes(cert.S))

	if err := c.stream.CloseSend(); err != nil {
		return nil, err
	}

	return certificate, nil
}
