package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

func (c *Client) Pedersen(dlog *dlog.ZpDLog, val big.Int) {
	(c.handler).pedersenCommitter = commitments.NewPedersenCommitter(dlog)

	initMsg := c.getInitialMsg()

	pf_i := getH(c, initMsg)
	pf := pf_i.(*pb.PedersenFirst)
	el := new(big.Int).SetBytes(pf.H)

	(c.handler).pedersenCommitter.SetH(el)

	commitment, err := (c.handler).pedersenCommitter.GetCommitMsg(&val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return
	}
	commit(c, commitment)

	decommitVal, r := c.handler.pedersenCommitter.GetDecommitMsg()
	decommit(c, decommitVal, r)
}
