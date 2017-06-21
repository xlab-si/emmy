package client

import (
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

type pedersenCommonClient struct {
	genericClient
}

func (c *pedersenCommonClient) decommit(decommitVal, r *big.Int) error {
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{
			&pb.PedersenDecommitment{
				X: decommitVal.Bytes(),
				R: r.Bytes(),
			},
		},
	}

	if _, err := c.getResponseTo(decommitMsg); err != nil {
		return err
	}
	return nil
}
