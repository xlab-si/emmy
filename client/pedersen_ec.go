package client

import (
	"github.com/xlab-si/emmy/crypto/commitments"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"math/big"
)

type PedersenECClient struct {
	pedersenCommonClient
	committer *commitments.PedersenECCommitter
	val       *big.Int
}

// NewPedersenECClient returns an initialized struct of type PedersenECClient.
func NewPedersenECClient(conn *grpc.ClientConn, v *big.Int) (*PedersenECClient, error) {
	genericClient, err := newGenericClient(conn)
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
	c.openStream()
	defer c.closeStream()

	ecge, err := c.getH()
	if err != nil {
		return err
	}
	my_ecge := types.ToECGroupElement(ecge)
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

func (c *PedersenECClient) commit(commitVal *types.ECGroupElement) error {
	commitmentMsg := &pb.Message{
		Content: &pb.Message_EcGroupElement{
			types.ToPbECGroupElement(commitVal),
		},
	}

	if _, err := c.getResponseTo(commitmentMsg); err != nil {
		return err
	}
	return nil
}
