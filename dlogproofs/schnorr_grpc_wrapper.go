package dlogproofs

import (
	"math/big"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"errors"
	"google.golang.org/grpc"
	"golang.org/x/net/context"
	"net"
	"log"
)

type SchnorrProtocolClient struct {
	client *pb.SchnorrProtocolClient	
	conn *grpc.ClientConn
	prover *SchnorrProver	
	protocolType common.ProtocolType
}

func NewSchnorrProtocolClient(protocolType common.ProtocolType) (*SchnorrProtocolClient, error) {
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		return nil, errors.New("could not connect")	
	}
		
	client := pb.NewSchnorrProtocolClient(conn)
	
  	prover, err := NewSchnorrProver(protocolType)
  	if err != nil {
		return nil, errors.New("could not create SchnorrProver")	
  	}
  	
	protocolClient := SchnorrProtocolClient {
		client: &client,
		conn: conn,
		prover: prover,
		protocolType: protocolType,
    }
    return &protocolClient, nil
}

// Sends H (see Pedersen receiver) to verifier (which acts as Pedersen committer)
//  and get a commitment to a challenge. It returns the commitment.
func (client *SchnorrProtocolClient) OpeningMsg() (*big.Int, error) {	
	h, p, q, g := client.prover.GetOpeningMsg()
	msg := &pb.PedersenFirst{H: h.Bytes(), P: p.Bytes(), 
		OrderOfSubgroup: q.Bytes(), G: g.Bytes()}
	reply, err := (*client.client).OpeningMsg(context.Background(), msg)
	if err != nil {
		return nil, err
	}
	
	commitment := new(big.Int).SetBytes(reply.X1)
	return commitment, nil
}

// Sends first message of sigma protocol and receives challenge decommitment.
func (client *SchnorrProtocolClient) ProofRandomData(secret *big.Int) (*big.Int, *big.Int, error) {
	x, t := client.prover.GetProofRandomData(secret)
    
	msg := &pb.SchnorrProofRandomData{X: x.Bytes(), P: client.prover.DLog.P.Bytes(), 
		OrderOfSubgroup: client.prover.DLog.GetOrderOfSubgroup().Bytes(), 
		G: client.prover.DLog.G.Bytes(), T: t.Bytes()}
		
	reply, err := (*client.client).ProofRandomData(context.Background(), msg)
	if err != nil {
		return nil, nil, err
	}
	challenge := new(big.Int).SetBytes(reply.X)
	r2 := new(big.Int).SetBytes(reply.R)
	
	return challenge, r2, nil
}

func (client *SchnorrProtocolClient) ProofData(challenge *big.Int) (bool, error) {	
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

func (client *SchnorrProtocolClient) Run(secret *big.Int) (bool, error) {	
	if client.protocolType != common.Sigma {
		commitment, _ := client.OpeningMsg() // sends pedersen's h=g^trapdoor
		client.prover.pedersenReceiver.SetCommitment(commitment)
	}

	challenge, r, err := client.ProofRandomData(secret)
	if err != nil {
		return false, err
	}
	
	success := true
	if client.protocolType != common.Sigma {
		success = client.prover.pedersenReceiver.CheckDecommitment(r, challenge)
	}
    	
	if success {
		proved, err := client.ProofData(challenge)
		if err != nil {
			return false, err
		}
		
		return proved, nil	
	} else {
		log.Println("Decommitment failed")
		return false, nil
	}
}

type SchnorrProtocolServer struct {
	// server acts as an interface to the Schnorr verifier
	verifier *SchnorrVerifier
	protocolType common.ProtocolType
}

func NewSchnorrProtocolServer(protocolType common.ProtocolType) *SchnorrProtocolServer {
	verifier := NewSchnorrVerifier(protocolType)
	protocolServer := SchnorrProtocolServer {
		verifier: verifier,
		protocolType: protocolType,
	}
	return &protocolServer
}

func (server *SchnorrProtocolServer) Listen() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()	
	
	pb.RegisterSchnorrProtocolServer(s, server)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (s *SchnorrProtocolServer) OpeningMsg(ctx context.Context, 
		msg *pb.PedersenFirst) (*pb.BigInt, error) {
	h := new(big.Int).SetBytes(msg.H)
	p := new(big.Int).SetBytes(msg.P)
	q := new(big.Int).SetBytes(msg.OrderOfSubgroup)
	g := new(big.Int).SetBytes(msg.G)
	
	s.verifier.SetCommitmentGroup(p, q, g)
	s.verifier.SetGroup(p, q, g)
	
	commitment := s.verifier.GetOpeningMsgReply(h)
	return &pb.BigInt{X1: commitment.Bytes()}, nil
}

func (s *SchnorrProtocolServer) ProofRandomData(ctx context.Context, 
		in *pb.SchnorrProofRandomData) (*pb.PedersenDecommitment, error) {
	p := new(big.Int).SetBytes(in.P)
	g := new(big.Int).SetBytes(in.G)
	q := new(big.Int).SetBytes(in.OrderOfSubgroup)
    
    // TODO: in reality, dlog can be fixed or probably at least chosen by a verifier, but
    // then dlog parameters would need to be communicated to the prover before the prover
    // sends ProofRandomData 
    
    x := new(big.Int).SetBytes(in.X)
    t := new(big.Int).SetBytes(in.T)
	s.verifier.SetProofRandomData(x, t)
	
	if s.protocolType == common.Sigma {
		s.verifier.SetGroup(p, q, g)
	}
	
	challenge, r2 := s.verifier.GetChallenge() // r2 is nil in sigma protocol
	if r2 == nil {
		r2 = new(big.Int)	
	}

	// pb.PedersenDecommitment is used also for SigmaProtocol (where there is no r2)
    return &pb.PedersenDecommitment{X: challenge.Bytes(), R: r2.Bytes()}, nil
}

func (s *SchnorrProtocolServer) ProofData(ctx context.Context, 
		in *pb.SchnorrProofData) (*pb.Status, error) {
	z := new(big.Int).SetBytes(in.Z)
	trapdoor := new(big.Int).SetBytes(in.Trapdoor)
	valid := s.verifier.Verify(z, trapdoor)

	return &pb.Status{Success: valid}, nil
}








