package client

import (
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

type PedersenClient struct {
	pedersenCommonClient
	committer *commitments.PedersenCommitter
	val       *big.Int
}

// NewPedersenClient returns an initialized struct of type PedersenClient.
func NewPedersenClient(endpoint string, variant pb.SchemaVariant, dlog *dlog.ZpDLog,
	val *big.Int) (*PedersenClient, error) {
	genericClient, err := newGenericClient(endpoint)
	if err != nil {
		return nil, err
	}

	validateVariant(variant)

	return &PedersenClient{
		pedersenCommonClient: pedersenCommonClient{genericClient: *genericClient},
		committer:            commitments.NewPedersenCommitter(dlog),
		val:                  val,
	}, nil
}

// Run runs Pedersen commitment protocol in multiplicative group of integers modulo p.
func (c *PedersenClient) Run() error {
	pf, err := c.getH()
	if err != nil {
		return err
	}

	el := new(big.Int).SetBytes(pf.H)
	c.committer.SetH(el)

	commitment, err := c.committer.GetCommitMsg(c.val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return err
	}

	if err = c.commit(commitment); err != nil {
		return err
	}

	decommitVal, r := c.committer.GetDecommitMsg()
	if err = c.decommit(decommitVal, r); err != nil {
		return err
	}

	if err := c.close(); err != nil {
		return err
	}
	return nil
}

func (c *PedersenClient) getH() (*pb.PedersenFirst, error) {
	initMsg := &pb.Message{
		ClientId: c.id,
		Schema:   pb.SchemaType_PEDERSEN,
		Content:  &pb.Message_Empty{&pb.EmptyMsg{}},
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}
	return resp.GetPedersenFirst(), nil
}

func (c *PedersenClient) commit(commitment *big.Int) error {
	commitmentMsg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: commitment.Bytes()},
		},
	}

	if _, err := c.getResponseTo(commitmentMsg); err != nil {
		return err
	}
	return nil
}

func validateVariant(v pb.SchemaVariant) {
	if v != pb.SchemaVariant_SIGMA {
		logger.Warningf("Pedersen protocol supports only SIGMA protocol (requested %v). Running SIGMA instead", v)
	}
}
