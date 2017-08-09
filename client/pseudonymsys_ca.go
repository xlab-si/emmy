package client

import (
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/pseudonymsys"
	"google.golang.org/grpc"
	"math/big"
)

type PseudonymsysCAClient struct {
	genericClient
	prover *dlogproofs.SchnorrProver
}

func NewPseudonymsysCAClient(conn *grpc.ClientConn) (*PseudonymsysCAClient, error) {
	dlog := config.LoadDLog("pseudonymsys")
	genericClient, err := newGenericClient(conn)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAClient{
		genericClient: *genericClient,
		prover:        dlogproofs.NewSchnorrProver(dlog, common.Sigma),
	}, nil
}

// ObtainCertificate provides a certificate from trusted CA to the user. Note that CA
// needs to know the user. The certificate is then used for registering pseudonym (nym).
// The certificate contains blinded user's master key pair and a signature of it.
func (c *PseudonymsysCAClient) ObtainCertificate(userSecret *big.Int, nym *pseudonymsys.Pseudonym) (
	*pseudonymsys.CACertificate, error) {
	c.openStream()
	defer c.closeStream()

	x := c.prover.GetProofRandomData(userSecret, nym.A)
	b, _ := c.prover.DLog.Exponentiate(nym.A, userSecret)
	pRandomData := pb.SchnorrProofRandomData{
		X: x.Bytes(),
		A: nym.A.Bytes(),
		B: b.Bytes(),
	}

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        pb.SchemaType_PSEUDONYMSYS_CA,
		SchemaVariant: pb.SchemaVariant_SIGMA,
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
