package server

import (
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/pseudonymsys"
	"math/big"
)

func (s *Server) PseudonymsysCA(req *pb.Message, stream pb.Protocol_RunServer) error {
	ca := pseudonymsys.NewCA()
	var err error

	sProofRandData := req.GetSchnorrProofRandomData()
	x := new(big.Int).SetBytes(sProofRandData.X)
	a := new(big.Int).SetBytes(sProofRandData.A)
	b := new(big.Int).SetBytes(sProofRandData.B)

	challenge := ca.GetChallenge(a, b, x)
	// pb.PedersenDecommitment is used also for SigmaProtocol (where there is no r2)
	resp := &pb.Message{
		Content: &pb.Message_PedersenDecommitment{
			&pb.PedersenDecommitment{
				X: challenge.Bytes(),
				R: new(big.Int).Bytes(), // r2 is nil in sigma protocol
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
	cert, err := ca.Verify(z)

	if err == nil {
		resp = &pb.Message{
			Content: &pb.Message_PseudonymsysCaCertificate{
				&pb.PseudonymsysCACertificate{
					BlindedA: cert.BlindedA.Bytes(),
					BlindedB: cert.BlindedB.Bytes(),
					R:        cert.R.Bytes(),
					S:        cert.S.Bytes(),
				},
			},
		}
	} else {
		resp = &pb.Message{
			Content: &pb.Message_PseudonymsysCaCertificate{
				&pb.PseudonymsysCACertificate{},
			},
			ProtocolError: err.Error(),
		}
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
