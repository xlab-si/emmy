package server

import (
	"github.com/xlab-si/emmy/common"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/pseudonymsys"
	"math/big"
)

func (s *Server) PseudonymsysCAEC(req *pb.Message, stream pb.Protocol_RunServer) error {
	ca := pseudonymsys.NewCAEC()
	var err error

	sProofRandData := req.GetSchnorrEcProofRandomData()
	x := common.ToECGroupElement(sProofRandData.X)
	a := common.ToECGroupElement(sProofRandData.A)
	b := common.ToECGroupElement(sProofRandData.B)

	challenge := ca.GetChallenge(a, b, x)
	resp := &pb.Message{
		Content: &pb.Message_Bigint{
			&pb.BigInt{
				X1: challenge.Bytes(),
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
			Content: &pb.Message_PseudonymsysCaCertificateEc{
				&pb.PseudonymsysCACertificateEC{
					BlindedA: common.ToPbECGroupElement(cert.BlindedA),
					BlindedB: common.ToPbECGroupElement(cert.BlindedB),
					R:        cert.R.Bytes(),
					S:        cert.S.Bytes(),
				},
			},
		}
	} else {
		resp = &pb.Message{
			Content: &pb.Message_PseudonymsysCaCertificateEc{
				&pb.PseudonymsysCACertificateEC{},
			},
			ProtocolError: err.Error(),
		}
	}

	if err = s.send(resp, stream); err != nil {
		return err
	}

	return nil
}
