package base

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	//"github.com/xlab-si/emmy/common"
	"log"
	//"math/big"
	//"sync"
)

//var streamMutex = &sync.Mutex{}

func (s *Server) PedersenEC() error {

	s.handler.pedersenECReciever = commitments.NewPedersenECReceiver()
	h := s.handler.pedersenECReciever.GetH()
	ecge := pb.ECGroupElement{X: h.X.Bytes(), Y: h.Y.Bytes()}
	resp := &pb.Message{Content: &pb.Message_EcGroupElement{&ecge}}

	err := s.send(resp)
	if err != nil {
		return err
	}

	log.Printf("[Server] Sent response 1")

	/*req, err := s.recieve()
	if err != nil {
		return err
	}

	log.Printf("[Server] Received request 2")

	ecgrop := req.GetEcGroupElement()
	log.Printf("I GOT THIS AS ECGE", ecgrop)

	if ecgrop == nil {
		log.Fatalf("[Server] got a nil ec group element ...")
		return nil
	}

	el := common.ToECGroupElement(ecgrop)
	s.handler.pedersenECReciever.SetCommitment(el)
	resp = &pb.Message{Content: &pb.Message_Empty{&pb.EmptyMsg{}}}
	err = s.send(resp)

	req, err = s.recieve() // this blocks
	if err != nil {
		//log.Fatalf("ERROR ERROR ERROR AFTER ECGE")
		return err
	} else {
		//log.Println("ALL GOOD AFTER ECGE")
		log.Printf("[Server] Sent response 2")
	}

	/*pedersenDecommitment := req.GetPedersenDecommitment()
	val := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)
	valid := s.handler.pedersenECReciever.CheckDecommitment(r, val)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	err = s.send(resp)*/

	return nil
}
