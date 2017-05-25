package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (c *Client) PedersenEC(val big.Int) {

	(c.handler).pedersenECCommitter = commitments.NewPedersenECCommitter()

	initMsg := &pb.Message{
		ClientId:      c.id,
		Schema:        c.schema,
		SchemaVariant: c.variant,
		Content:       &pb.Message_Empty{&pb.EmptyMsg{}},
	}

	err := c.send(initMsg)
	if err != nil {
		return
	}

	resp, err := c.recieve()
	if err != nil {
		return
	}

	ecge := common.ToECGroupElement(resp.GetEcGroupElement())
	(c.handler).pedersenECCommitter.SetH(ecge)

	commitment, err := c.handler.pedersenECCommitter.GetCommitMsg(&val)
	if err != nil {
		logger.Criticalf("could not generate committment message: %v", err)
		return
	}

	my_ecge := common.ToPbECGroupElement(commitment)
	commitmentMsg := &pb.Message{Content: &pb.Message_EcGroupElement{my_ecge}}

	err = c.send(commitmentMsg)
	if err != nil {
		return
	}

	resp, err = c.recieve()
	if err != nil {
		return
	}

	decommitVal, r := c.handler.pedersenECCommitter.GetDecommitMsg()
	decommitment := &pb.PedersenDecommitment{X: decommitVal.Bytes(), R: r.Bytes()}
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{decommitment},
	}

	err = c.send(decommitMsg)
	if err != nil {
		return
	}
	resp, err = c.recieve()
	if err != nil {
		return
	}
}
