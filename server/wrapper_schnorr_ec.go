package main

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlogproofs"
	"math/big"
)

func (s *Server) SchnorrEC(req *pb.Message, protocolType common.ProtocolType, stream pb.Protocol_RunServer) error {

	verifier := dlogproofs.NewSchnorrECVerifier(protocolType)

	if protocolType != common.Sigma {
		// ZKP, ZKPOK
		ecge := req.GetEcGroupElement()
		h := common.ToECGroupElement(ecge)
		commitment := verifier.GetOpeningMsgReply(h)
		pb_ecge := common.ToPbECGroupElement(commitment)

		resp := &pb.Message{
			Content: &pb.Message_EcGroupElement{
				pb_ecge,
			},
		}

		err := s.send(resp, stream)
		if err != nil {
			return err
		}

		req, err = s.recieve(stream)
		if err != nil {
			return err
		}
	}

	sProofRandData := req.GetSchnorrEcProofRandomData()

	x := common.ToECGroupElement(sProofRandData.X)
	a := common.ToECGroupElement(sProofRandData.A)
	b := common.ToECGroupElement(sProofRandData.B)
	verifier.SetProofRandomData(x, a, b)

	challenge, r2 := verifier.GetChallenge() // r2 is nil in sigma protocol
	if r2 == nil {
		r2 = new(big.Int)
	}

	// pb.PedersenDecommitment is used also for SigmaProtocol (where there is no r2)
	resp := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{
			&pb.PedersenDecommitment{
				X: challenge.Bytes(),
				R: r2.Bytes(),
			},
		},
	}

	err := s.send(resp, stream)
	if err != nil {
		return err
	}

	req, err = s.recieve(stream)
	if err != nil {
		return err
	}

	sProofData := req.GetSchnorrProofData()
	z := new(big.Int).SetBytes(sProofData.Z)
	trapdoor := new(big.Int).SetBytes(sProofData.Trapdoor)
	valid := verifier.Verify(z, trapdoor)

	resp = &pb.Message{
		Content: &pb.Message_Status{&pb.Status{Success: valid}},
	}

	err = s.send(resp, stream)
	if err != nil {
		return err
	}

	return nil
}
