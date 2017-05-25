package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
	"math/big"
)

func (s *Server) Pedersen(dlog *dlog.ZpDLog, stream pb.Protocol_RunServer) error {

	pedersenReciever := commitments.NewPedersenReceiver(dlog)

	h := pedersenReciever.GetH()

	pedersenFirst := pb.PedersenFirst{
		H: h.Bytes(),
	}
	resp := &pb.Message{Content: &pb.Message_PedersenFirst{&pedersenFirst}}

	err := s.send(resp, stream)
	if err != nil {
		return err
	}

	req, err := s.recieve(stream)
	if err != nil {
		return err
	}

	bigint := req.GetBigint()
	el := new(big.Int).SetBytes(bigint.X1)
	pedersenReciever.SetCommitment(el)
	resp = &pb.Message{Content: &pb.Message_Empty{&pb.EmptyMsg{}}}

	err = s.send(resp, stream)
	if err != nil {
		return err
	}

	req, err = s.recieve(stream)
	if err != nil {
		return err
	}

	pedersenDecommitment := req.GetPedersenDecommitment()
	val := new(big.Int).SetBytes(pedersenDecommitment.X)
	r := new(big.Int).SetBytes(pedersenDecommitment.R)
	valid := pedersenReciever.CheckDecommitment(r, val)

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
