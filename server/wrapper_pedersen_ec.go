package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"math/big"
)

func (s *Server) PedersenEC(stream pb.Protocol_RunServer) error {

	pedersenECReciever := commitments.NewPedersenECReceiver()
	h := pedersenECReciever.GetH()
	ecge := pb.ECGroupElement{X: h.X.Bytes(), Y: h.Y.Bytes()}
	resp := &pb.Message{Content: &pb.Message_EcGroupElement{&ecge}}

	err := s.send(resp, stream)
	if err != nil {
		return err
	}

	req, err := s.recieve(stream)
	if err != nil {
		return err
	}

	ecgrop := req.GetEcGroupElement()
	if ecgrop == nil {
		logger.Critical("Got a nil EC group element")
		return nil
	}

	el := common.ToECGroupElement(ecgrop)
	pedersenECReciever.SetCommitment(el)
	resp = &pb.Message{Content: &pb.Message_Empty{&pb.EmptyMsg{}}}
	err = s.send(resp, stream)

	req, err = s.recieve(stream)
	if err != nil {
		return err
	}

	pedersenDecommitment := req.GetPedersenDecommitment()
	val := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)
	valid := pedersenECReciever.CheckDecommitment(r, val)

	logger.Noticef("Commitment scheme success: **%v**", valid)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	err = s.send(resp, stream)
	if err != nil {
		return err
	}

	return nil
}
