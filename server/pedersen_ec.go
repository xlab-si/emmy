package server

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (s *Server) PedersenEC(stream pb.Protocol_RunServer) error {
	pedersenECReceiver := commitments.NewPedersenECReceiver()

	h := pedersenECReceiver.GetH()
	ecge := pb.ECGroupElement{
		X: h.X.Bytes(),
		Y: h.Y.Bytes(),
	}
	resp := &pb.Message{Content: &pb.Message_EcGroupElement{&ecge}}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	ecgrop := req.GetEcGroupElement()
	if ecgrop == nil {
		logger.Critical("Got a nil EC group element")
		return err
	}

	el := common.ToECGroupElement(ecgrop)
	pedersenECReceiver.SetCommitment(el)
	resp = &pb.Message{Content: &pb.Message_Empty{&pb.EmptyMsg{}}}
	if err = s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
	if err != nil {
		return err
	}

	pedersenDecommitment := req.GetPedersenDecommitment()
	val := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)
	valid := pedersenECReceiver.CheckDecommitment(r, val)

	logger.Noticef("Commitment scheme success: **%v**", valid)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
