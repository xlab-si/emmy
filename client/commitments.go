package client

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (c *Client) getH(initMsg *pb.Message) interface{} {
	initMsg.Content = &pb.Message_Empty{&pb.EmptyMsg{}}

	if err := c.send(initMsg); err != nil {
		return err
	}

	resp, err := c.receive()
	if err != nil {
		return err
	}

	if c.schema == pb.SchemaType_PEDERSEN {
		return resp.GetPedersenFirst()
	}
	return resp.GetEcGroupElement()
}

func (c *Client) commit(commitment interface{}) error {
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

	if err := c.send(commitmentMsg); err != nil {
		return err
	}

	if _, err := c.receive(); err != nil {
		return err
	}

	return nil
}

func (c *Client) decommit(decommitVal, r *big.Int) error {
	decommitment := &pb.PedersenDecommitment{
		X: decommitVal.Bytes(),
		R: r.Bytes(),
	}
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{decommitment},
	}

	if err := c.send(decommitMsg); err != nil {
		return err
	}

	if _, err := c.receive(); err != nil {
		return err
	}

	return nil
}
