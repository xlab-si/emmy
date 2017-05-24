package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	//"github.com/xlab-si/emmy/common"
	"log"
	"math/big"
)

func (c *Client) PedersenEC(val big.Int) { // error

	(c.handler).pedersenECCommitter = commitments.NewPedersenECCommitter()

	initMsg := c.getInitialMsg()
	initMsg.Content = &pb.Message_Empty{&pb.EmptyMsg{}}

	err := c.send(initMsg)
	if err != nil {
		//return err
		log.Fatalf("[Client %v] ERROR: %v", c.id, err)
	}

	log.Printf("[Client %v] Sent request 1", c.id)

	_, err = c.recieve()
	if err != nil {
		//return err
		log.Fatalf("[Client %v] ERROR: %v", c.id, err)
	}

	/*log.Printf("[Client] Received response 1")
	//return //nil

	log.Printf("[Client %v] I GOT THIS IN THE MESSAGE: %v", &c, resp.GetEcGroupElement())
	ecge := common.ToECGroupElement(resp.GetEcGroupElement())
	(c.handler).pedersenECCommitter.SetH(ecge)

	commitment, err := c.handler.pedersenECCommitter.GetCommitMsg(&val)
	if err != nil {
		log.Fatalf("could not generate committment message: %v", err)
	}

	my_ecge := common.ToPbECGroupElement(commitment)
	commitmentMsg := &pb.Message{Content: &pb.Message_EcGroupElement{my_ecge}}

	err = c.send(commitmentMsg)
	if err != nil {
		//return err
		log.Fatalf("[Client] ERROR: %v", err)
	}

	log.Printf("[Client] Sent request 2")

	resp, err = c.recieve()
	if err != nil {
		//return err
		log.Fatalf("[Client] ERROR: %v", err)
	}

	log.Printf("[Client] Received response 2")

	/*decommitVal, r := c.handler.pedersenECCommitter.GetDecommitMsg()
	decommitment := &pb.PedersenDecommitment{X: decommitVal.Bytes(), R: r.Bytes()}
	decommitMsg := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{decommitment},
	}

	err = c.send(decommitMsg)
	if err != nil {
		return //err
	}
	resp, err = c.recieve()
	if err != nil {
		return //err
	}

	//(*c.stream).CloseSend()
	//(*c.conn).Close()
	*/
	log.Printf("[Client %v] ************ DONE ************", c.id)

	//return nil
}
