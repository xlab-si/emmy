package server

import (
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/qrproofs"
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

func (s *Server) QR(req *pb.Message, dlog *dlog.ZpDLog,
	stream pb.Protocol_RunServer) error {

	initMsg := req.GetBigint()
	y := new(big.Int).SetBytes(initMsg.X1)
	verifier := qrproofs.NewQRVerifier(y, dlog)
	var err error

	resp := &pb.Message{
		Content: &pb.Message_Empty{&pb.EmptyMsg{}},
	}
	if err := s.send(resp, stream); err != nil {
		return err
	}

	m := dlog.P.BitLen()
	// the client has to prove for all i - if in one iteration the knowledge
	// is not proved, the protocol is stopped
	for i := 0; i < m; i++ {
		req, err = s.receive(stream)
		if err != nil {
			return err
		}
		proofRandomData := new(big.Int).SetBytes(req.GetBigint().X1)
		challenge := verifier.GetChallenge(proofRandomData)

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

		req, err := s.receive(stream)
		if err != nil {
			return err
		}

		proofData := req.GetBigint()
		z := new(big.Int).SetBytes(proofData.X1)
		proved := verifier.Verify(z)

		resp = &pb.Message{
			Content: &pb.Message_Status{&pb.Status{Success: proved}},
		}

		if err = s.send(resp, stream); err != nil {
			return err
		}

		if !proved {
			break
		}
	}

	return nil
}
