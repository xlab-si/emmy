package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (c *Client) PedersenEC(val big.Int) {

	(c.handler).pedersenECCommitter = commitments.NewPedersenECCommitter()

	initMsg := c.getInitialMsg()
	ecge_i := getH(c, initMsg)
	ecge := ecge_i.(*pb.ECGroupElement)
	my_ecge := common.ToECGroupElement(ecge)

	(c.handler).pedersenECCommitter.SetH(my_ecge)

	commitment, err := c.handler.pedersenECCommitter.GetCommitMsg(&val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return
	}
	commit(c, commitment)

	decommitVal, r := c.handler.pedersenECCommitter.GetDecommitMsg()
	decommit(c, decommitVal, r)
}
