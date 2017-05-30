package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (c *Client) PedersenEC(val big.Int) error {

	(c.handler).pedersenECCommitter = commitments.NewPedersenECCommitter()

	initMsg := c.getInitialMsg()
	resInterface := getH(c, initMsg)

	ecge, success := resInterface.(*pb.ECGroupElement)
	if !success {
		return resInterface.(error)
	}

	my_ecge := common.ToECGroupElement(ecge)

	(c.handler).pedersenECCommitter.SetH(my_ecge)

	commitment, err := c.handler.pedersenECCommitter.GetCommitMsg(&val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return nil
	}
	err = commit(c, commitment)
	if err != nil {
		return err
	}

	decommitVal, r := c.handler.pedersenECCommitter.GetDecommitMsg()
	err = decommit(c, decommitVal, r)
	if err != nil {
		return err
	}

	return nil
}
