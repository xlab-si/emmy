package server

import (
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

func (s *Server) Pedersen(dlog *dlog.ZpDLog, stream pb.Protocol_RunServer) error {
	pedersenReceiver := commitments.NewPedersenReceiver(dlog)

	h := pedersenReceiver.GetH()

	pedersenFirst := pb.PedersenFirst{
		H: h.Bytes(),
	}
	resp := &pb.Message{Content: &pb.Message_PedersenFirst{&pedersenFirst}}

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	bigint := req.GetBigint()
	el := new(big.Int).SetBytes(bigint.X1)
	pedersenReceiver.SetCommitment(el)
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
	valid := pedersenReceiver.CheckDecommitment(r, val)

	logger.Noticef("Commitment scheme success: **%v**", valid)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
