package server

import (
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/dlogproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

func (s *Server) SchnorrEC(req *pb.Message, protocolType types.ProtocolType,
	stream pb.Protocol_RunServer, curve dlog.Curve) error {
	verifier := dlogproofs.NewSchnorrECVerifier(curve, protocolType)
	var err error

	if protocolType != types.Sigma {
		// ZKP, ZKPOK
		ecge := req.GetEcGroupElement()
		h := types.ToECGroupElement(ecge)
		commitment := verifier.GetOpeningMsgReply(h)
		pb_ecge := types.ToPbECGroupElement(commitment)

		resp := &pb.Message{
			Content: &pb.Message_EcGroupElement{
				pb_ecge,
			},
		}

		if err := s.send(resp, stream); err != nil {
			return err
		}

		req, err = s.receive(stream)
		if err != nil {
			return err
		}
	}

	sProofRandData := req.GetSchnorrEcProofRandomData()

	x := types.ToECGroupElement(sProofRandData.X)
	a := types.ToECGroupElement(sProofRandData.A)
	b := types.ToECGroupElement(sProofRandData.B)
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

	if err := s.send(resp, stream); err != nil {
		return err
	}

	req, err = s.receive(stream)
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

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
