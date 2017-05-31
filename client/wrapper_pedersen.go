package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

func (c *Client) Pedersen(dlog *dlog.ZpDLog, val big.Int) error {
	(c.handler).pedersenCommitter = commitments.NewPedersenCommitter(dlog)

	initMsg := c.getInitialMsg()

	resInterface := getH(c, initMsg)

	pf, success := resInterface.(*pb.PedersenFirst)
	if !success {
		return resInterface.(error)
	}

	el := new(big.Int).SetBytes(pf.H)

	(c.handler).pedersenCommitter.SetH(el)

	commitment, err := (c.handler).pedersenCommitter.GetCommitMsg(&val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return err
	}
	err = commit(c, commitment)
	if err != nil {
		return err
	}

	decommitVal, r := c.handler.pedersenCommitter.GetDecommitMsg()
	err = decommit(c, decommitVal, r)
	if err != nil {
		return err
	}

	return nil
}
