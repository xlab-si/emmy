package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

type PedersenECClient struct {
	pedersenCommonClient
	committer *commitments.PedersenECCommitter
	val       *big.Int
}

// NewPedersenECClient returns an initialized struct of type PedersenECClient.
func NewPedersenECClient(endpoint string, v *big.Int) (*PedersenECClient, error) {
	genericClient, err := newGenericClient(endpoint)
	if err != nil {
		return nil, err
	}

	return &PedersenECClient{
		pedersenCommonClient: pedersenCommonClient{genericClient: *genericClient},
		committer:            commitments.NewPedersenECCommitter(),
		val:                  v,
	}, nil
}

// Run runs Pedersen commitment protocol in the eliptic curve group.
func (c *PedersenECClient) Run() error {
	ecge, err := c.getH()
	if err != nil {
		return err
	}
	my_ecge := common.ToECGroupElement(ecge)
	c.committer.SetH(my_ecge)

	commitment, err := c.committer.GetCommitMsg(c.val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return nil
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

func (c *PedersenECClient) getH() (*pb.ECGroupElement, error) {
	initMsg := &pb.Message{
		ClientId: c.id,
		Schema:   pb.SchemaType_PEDERSEN_EC,
		Content:  &pb.Message_Empty{&pb.EmptyMsg{}},
	}

	resp, err := c.getResponseTo(initMsg)
	if err != nil {
		return nil, err
	}
	return resp.GetEcGroupElement(), nil
}

func (c *PedersenECClient) commit(commitVal *common.ECGroupElement) error {
	commitmentMsg := &pb.Message{
		Content: &pb.Message_EcGroupElement{
			common.ToPbECGroupElement(commitVal),
		},
	}

	if _, err := c.getResponseTo(commitmentMsg); err != nil {
		return err
	}
	return nil
}
