package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (c *Client) PedersenEC(val *big.Int) error {
	c.handler.pedersenECCommitter = commitments.NewPedersenECCommitter()

	initMsg := c.getInitialMsg()
	resInterface := c.getH(initMsg)

	ecge, success := resInterface.(*pb.ECGroupElement)
	if !success {
		return resInterface.(error)
	}

	my_ecge := common.ToECGroupElement(ecge)

	c.handler.pedersenECCommitter.SetH(my_ecge)

	commitment, err := c.handler.pedersenECCommitter.GetCommitMsg(val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return nil
	}

	if err = c.commit(commitment); err != nil {
		return err
	}

	decommitVal, r := c.handler.pedersenECCommitter.GetDecommitMsg()
	if err = c.decommit(decommitVal, r); err != nil {
		return err
	}

	return nil
}
