package server

import (
	"fmt"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/qrproofs"
	"math/big"
)

func (s *Server) QNR(req *pb.Message, qr *dlog.QR,
	stream pb.Protocol_RunServer) error {

	initMsg := req.GetBigint()
	y := new(big.Int).SetBytes(initMsg.X1)
	resp := &pb.Message{
		Content: &pb.Message_Empty{&pb.EmptyMsg{}},
	}
	if err := s.send(resp, stream); err != nil {
		return err
	}

	verifier := qrproofs.NewQNRVerifier(qr, y)
	var err error

	m := qr.N.BitLen()
	// the client has to prove for all i - if in one iteration the knowledge
	// is not proved, the protocol is stopped
	for i := 0; i < m; i++ {
		req, err = s.receive(stream)
		if err != nil {
			return err
		}

		if req.GetEmpty() == nil {
			return fmt.Errorf("Shoud receive empty message at this point")
		}

		w, pairs := verifier.GetChallenge()
		pbPairs := []*pb.Pair{}

		for j := 0; j < m; j++ {
			pbPairs = append(pbPairs, common.ToPbPair(pairs[j]))
		}

		resp := &pb.Message{
			Content: &pb.Message_QnrVerifierChallenge{
				&pb.QNRVerifierChallenge{
					W:     w.Bytes(),
					Pairs: pbPairs,
				},
			},
		}

		if err = s.send(resp, stream); err != nil {
			return err
		}

		req, err := s.receive(stream)
		if err != nil {
			return err
		}

		proverChallenge := req.GetRepeatedInt()

		var randVector []int
		for _, i := range proverChallenge.Ints {
			randVector = append(randVector, int(i))
		}
		verProofPairs := verifier.GetProofData(randVector)
		var verProofPbPairs []*pb.Pair
		for _, p := range verProofPairs {
			pbPair := common.ToPbPair(p)
			verProofPbPairs = append(verProofPbPairs, pbPair)
		}

		resp = &pb.Message{
			Content: &pb.Message_RepeatedPair{
				&pb.RepeatedPair{
					Pairs: verProofPbPairs,
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

		typ := req.GetEint()
		proved := verifier.Verify(int(typ))

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
