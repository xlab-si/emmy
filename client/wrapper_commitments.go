package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func getH(c *Client, initMsg *pb.Message) interface{} {
	initMsg.Content = &pb.Message_Empty{&pb.EmptyMsg{}}

	err := c.send(initMsg)
	if err != nil {
		return nil
	}

	resp, err := c.recieve()
	if err != nil {
		return nil
	}

	if c.schema == pb.SchemaType_PEDERSEN {
		return resp.GetPedersenFirst()
	}
	return resp.GetEcGroupElement()
}

func commit(c *Client, commitment interface{}) {
	commitmentMsg := &pb.Message{}

	if c.schema == pb.SchemaType_PEDERSEN {
		commitVal := commitment.(*big.Int)
		bigint := &pb.BigInt{X1: commitVal.Bytes()}
		commitMsgContent := &pb.Message_Bigint{bigint}
		commitmentMsg.Content = commitMsgContent
	} else {
		commitVal := commitment.(*common.ECGroupElement)
		ecge := common.ToPbECGroupElement(commitVal)
		commitMsgContent := &pb.Message_EcGroupElement{ecge}
		commitmentMsg.Content = commitMsgContent
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
	decommitment := &pb.PedersenDecommitment{
		X: decommitVal.Bytes(),
		R: r.Bytes(),
	}
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
