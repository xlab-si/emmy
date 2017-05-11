package dlogproofs

import (
	"math/big"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
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

func NewSchnorrProtocolClient(dlog *dlog.ZpDLog, 
		protocolType common.ProtocolType) (*SchnorrProtocolClient, error) {
    conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		return nil, errors.New("could not connect")	
	}
		
	client := pb.NewSchnorrProtocolClient(conn)
	
  	prover := NewSchnorrProver(dlog, protocolType)
  	
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
	h := client.prover.GetOpeningMsg()
	msg := &pb.PedersenFirst{H: h.Bytes()}
	reply, err := (*client.client).OpeningMsg(context.Background(), msg)
	if err != nil {
		return nil, err
	}
	
	commitment := new(big.Int).SetBytes(reply.X1)
	return commitment, nil
}

// Sends first message of sigma protocol and receives challenge decommitment.
func (client *SchnorrProtocolClient) ProofRandomData(a, secret *big.Int) (*big.Int, *big.Int, error) {
	x := client.prover.GetProofRandomData(secret, a)
    
    b, _ := client.prover.DLog.Exponentiate(a, secret)
	msg := &pb.SchnorrProofRandomData{X: x.Bytes(), A: a.Bytes(), B: b.Bytes()}
		
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

func (client *SchnorrProtocolClient) Run(a, secret *big.Int) (bool, error) {	
	if client.protocolType != common.Sigma {
		commitment, _ := client.OpeningMsg() // sends pedersen's h=g^trapdoor
		client.prover.pedersenReceiver.SetCommitment(commitment)
	}

	challenge, r, err := client.ProofRandomData(a, secret)
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

func NewSchnorrProtocolServer(dlog *dlog.ZpDLog, 
		protocolType common.ProtocolType) *SchnorrProtocolServer {
	verifier := NewSchnorrVerifier(dlog, protocolType)
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
	commitment := s.verifier.GetOpeningMsgReply(h)
	return &pb.BigInt{X1: commitment.Bytes()}, nil
}

func (s *SchnorrProtocolServer) ProofRandomData(ctx context.Context, 
		in *pb.SchnorrProofRandomData) (*pb.PedersenDecommitment, error) {
    x := new(big.Int).SetBytes(in.X)
    a := new(big.Int).SetBytes(in.A)
    b := new(big.Int).SetBytes(in.B)
	s.verifier.SetProofRandomData(x, a, b)
	
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








