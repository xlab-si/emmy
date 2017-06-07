package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

func (c *Client) Pedersen(dlog *dlog.ZpDLog, val *big.Int) error {
	c.handler.pedersenCommitter = commitments.NewPedersenCommitter(dlog)

	initMsg := c.getInitialMsg()

	resInterface := c.getH(initMsg)

	pf, success := resInterface.(*pb.PedersenFirst)
	if !success {
		return resInterface.(error)
	}

	el := new(big.Int).SetBytes(pf.H)

	c.handler.pedersenCommitter.SetH(el)

	commitment, err := c.handler.pedersenCommitter.GetCommitMsg(val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return err
	}

	if err = c.commit(commitment); err != nil {
		return err
	}

	decommitVal, r := c.handler.pedersenCommitter.GetDecommitMsg()
	if err = c.decommit(decommitVal, r); err != nil {
		return err
	}

	return nil
}
