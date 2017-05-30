package dlogproofs

import (
	"errors"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"math/big"
	"net"
)

type SchnorrECProtocolClient struct {
	client       *pb.SchnorrECProtocolClient
	conn         *grpc.ClientConn
	prover       *SchnorrECProver
	protocolType common.ProtocolType
}

func NewSchnorrECProtocolClient(protocolType common.ProtocolType) (*SchnorrECProtocolClient, error) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		return nil, errors.New("could not connect")
	}

	client := pb.NewSchnorrECProtocolClient(conn)
	prover, err := NewSchnorrECProver(protocolType)
	if err != nil {
		return nil, errors.New("could not create SchnorrECProver")
	}

	protocolClient := SchnorrECProtocolClient{
		client:       &client,
		conn:         conn,
		prover:       prover,
		protocolType: protocolType,
	}
	return &protocolClient, nil
}

// Sends H (see Pedersen receiver) to verifier (which acts as Pedersen committer)
//  and get a commitment to a challenge. It returns the commitment.
func (client *SchnorrECProtocolClient) OpeningMsg() (*common.ECGroupElement, error) {
	h := client.prover.GetOpeningMsg()
	msg := common.ToPbECGroupElement(h)
	reply, err := (*client.client).OpeningMsg(context.Background(), msg)
	if err != nil {
		return nil, err
	}

	commitment := common.ToECGroupElement(reply)

	return commitment, nil
}

// Sends first message of sigma protocol and receives challenge decommitment.
func (client *SchnorrECProtocolClient) ProofRandomData(a *common.ECGroupElement,
	secret *big.Int) (*big.Int, *big.Int, error) {
	x := client.prover.GetProofRandomData(secret, a) // x = a^r, b = a^secret is "public key"

	b1, b2 := client.prover.DLog.Exponentiate(a.X, a.Y, secret)
	b := &common.ECGroupElement{X: b1, Y: b2}
	msg := &pb.SchnorrECProofRandomData{X: common.ToPbECGroupElement(x),
		A: common.ToPbECGroupElement(a), B: common.ToPbECGroupElement(b)}

	reply, err := (*client.client).ProofRandomData(context.Background(), msg) // contains (challenge, r2)
	if err != nil {
		return nil, nil, err
	}
	challenge := new(big.Int).SetBytes(reply.X)
	r2 := new(big.Int).SetBytes(reply.R)

	return challenge, r2, nil
}

func (client *SchnorrECProtocolClient) ProofData(challenge *big.Int) (bool, error) {
	z, trapdoor := client.prover.GetProofData(challenge)
	if trapdoor == nil { // sigma protocol and ZKP
		trapdoor = new(big.Int)
	}
	msg := &pb.SchnorrProofData{Z: z.Bytes(), Trapdoor: trapdoor.Bytes()}

	status, err := (*client.client).ProofData(context.Background(), msg)
	if err != nil {
		return false, err
	}
	return status.Success, nil
}

func (client *SchnorrECProtocolClient) Run(a *common.ECGroupElement, secret *big.Int) (bool, error) {
	if client.protocolType != common.Sigma {
		commitment, _ := client.OpeningMsg() // sends pedersen's h=g^trapdoor
		client.prover.PedersenReceiver.SetCommitment(commitment)
	}

	challenge, r, err := client.ProofRandomData(a, secret) // we are proving that we know secret
	if err != nil {
		return false, err
	}

	success := true
	if client.protocolType != common.Sigma {
		success = client.prover.PedersenReceiver.CheckDecommitment(r, challenge)
	}

	if success {
		proved, _ := client.ProofData(challenge)
		if err != nil {
			return false, err
		}
		return proved, nil
	} else {
		log.Println("Decommitment failed")
		return false, nil
	}
}

type SchnorrECProtocolServer struct {
	// server acts as an interface to the Schnorr verifier
	verifier *SchnorrECVerifier
}

func NewSchnorrECProtocolServer(protocolType common.ProtocolType) *SchnorrECProtocolServer {
	verifier := NewSchnorrECVerifier(protocolType)
	protocolServer := SchnorrECProtocolServer{
		verifier: verifier,
	}

	return &protocolServer
}

func (server *SchnorrECProtocolServer) Listen() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	pb.RegisterSchnorrECProtocolServer(s, server)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (s *SchnorrECProtocolServer) OpeningMsg(ctx context.Context,
	msg *pb.ECGroupElement) (*pb.ECGroupElement, error) {
	h := common.ToECGroupElement(msg)
	commitment := s.verifier.GetOpeningMsgReply(h)

	return common.ToPbECGroupElement(commitment), nil
}

func (s *SchnorrECProtocolServer) ProofRandomData(ctx context.Context,
	in *pb.SchnorrECProofRandomData) (*pb.PedersenDecommitment, error) {
	x := common.ToECGroupElement(in.X)
	a := common.ToECGroupElement(in.A)
	b := common.ToECGroupElement(in.B)
	s.verifier.SetProofRandomData(x, a, b)
	challenge, r2 := s.verifier.GetChallenge() // r2 is nil in sigma protocol
	if r2 == nil {
		r2 = new(big.Int)
	}

	// pb.PedersenDecommitment is used also for SigmaProtocol (where there is no r2)
	return &pb.PedersenDecommitment{X: challenge.Bytes(), R: r2.Bytes()}, nil
}

func (s *SchnorrECProtocolServer) ProofData(ctx context.Context,
	in *pb.SchnorrProofData) (*pb.Status, error) {
	z := new(big.Int).SetBytes(in.Z)
	trapdoor := new(big.Int).SetBytes(in.Trapdoor)
	valid := s.verifier.Verify(z, trapdoor)

	return &pb.Status{Success: valid}, nil
}
