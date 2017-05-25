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

	pf := getH(c, initMsg)
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

func getH(c *Client, initMsg *pb.Message) *pb.PedersenFirst {
	initMsg.Content = &pb.Message_Empty{&pb.EmptyMsg{}}

	err := c.send(initMsg)
	if err != nil {
		return nil
	}

	resp, err := c.recieve()
	if err != nil {
		return nil
	}

	return resp.GetPedersenFirst()
}

func commit(c *Client, commitment *big.Int) {
	commitmentMsg := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{X1: commitment.Bytes()},
		},
	}

	err := c.send(commitmentMsg)
	if err != nil {
		return
	}

	_, err = c.recieve()
	if err != nil {
		return
	}
}

func decommit(c *Client, decommitVal, r *big.Int) {
	decommitment := &pb.PedersenDecommitment{X: decommitVal.Bytes(), R: r.Bytes()}
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{decommitment},
	}

	err := c.send(decommitMsg)
	if err != nil {
		return
	}
	_, err = c.recieve()
	if err != nil {
		return
	}
}
