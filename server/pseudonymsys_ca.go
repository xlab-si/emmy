package server

import (
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/pseudonymsys"
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

func (s *Server) PseudonymsysCA(req *pb.Message, stream pb.Protocol_RunServer) error {
	var err error

	dlog := config.LoadDLog("pseudonymsys")
	d := config.LoadPseudonymsysCASecret()
	pubKeyX, pubKeyY := config.LoadPseudonymsysCAPubKey()
	ca := pseudonymsys.NewCA(dlog, d, pubKeyX, pubKeyY)

	sProofRandData := req.GetSchnorrProofRandomData()
	x := new(big.Int).SetBytes(sProofRandData.X)
	a := new(big.Int).SetBytes(sProofRandData.A)
	b := new(big.Int).SetBytes(sProofRandData.B)

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
