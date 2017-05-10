package commitments

import (
	"math/big"
	"net"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/dlog"
	"log"
)

type PedersenProtocolClient struct {
	client *pb.PedersenClient	
	conn *grpc.ClientConn
	committer *PedersenCommitter	
}

func NewPedersenProtocolClient(dlog *dlog.ZpDLog) *PedersenProtocolClient {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
		
	client := pb.NewPedersenClient(conn)
  	committer := NewPedersenCommitter(dlog)
  		
	protocolClient := PedersenProtocolClient {
		client: &client,
		conn: conn,
		committer: committer,
    }
    return &protocolClient
}

func (client *PedersenProtocolClient) ObtainH() (error) {
  	// ask commitment receiver for h:
	reply, err := (*client.client).GetH(context.Background(), &pb.EmptyMsg{})
	if err != nil {
		log.Fatalf("could not get h: %v", err)
	}
		
	el := new(big.Int).SetBytes(reply.H)
    (*client.committer).SetH(el)
    return nil
}

func (client *PedersenProtocolClient) Commit(x *big.Int) (bool, error) {
	commitment, err := client.committer.GetCommitMsg(x)
	if err != nil {
		log.Fatalf("could not generate committment message: %v", err)
	}
	
	log.Println("committing..........")
	_, err = (*client.client).Commit(context.Background(), &pb.BigInt{X1: commitment.Bytes()})
	if err != nil {
		log.Fatalf("could not commit: %v", err)
	}
	
	return true, err
}

func (client *PedersenProtocolClient) Decommit() (bool, error) {
	val, r := client.committer.GetDecommitMsg()
	
	log.Println("decommitting..........")
	reply, err := (*client.client).Decommit(context.Background(), &pb.PedersenDecommitment{X: val.Bytes(), R: r.Bytes()})
	if err != nil {
		log.Fatalf("could not decommit: %v", err)
	}
	
	client.conn.Close()
	return reply.Success, err
}


type PedersenProtocolServer struct {
	receiver *PedersenReceiver
}

func NewPedersenProtocolServer(dlog *dlog.ZpDLog) *PedersenProtocolServer {
	receiver := NewPedersenReceiver(dlog)
	protocolServer := PedersenProtocolServer {
		receiver: receiver,
	}

	return &protocolServer
}

func (server *PedersenProtocolServer) Listen() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()	
	
	pb.RegisterPedersenServer(s, server)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (s *PedersenProtocolServer) GetH(ctx context.Context, 
		in *pb.EmptyMsg) (*pb.PedersenFirst, error) {
	h := s.receiver.GetH() // we could as well use s.receiver.h as h is defined in the same package and thus accessible from here
		
	return &pb.PedersenFirst{H: h.Bytes()}, nil
}

func (s *PedersenProtocolServer) Commit(ctx context.Context, 
		in *pb.BigInt) (*pb.EmptyMsg, error) {
	el := new(big.Int).SetBytes(in.X1)
	s.receiver.SetCommitment(el)
	return &pb.EmptyMsg{}, nil
}

func (s *PedersenProtocolServer) Decommit(ctx context.Context, 
		in *pb.PedersenDecommitment) (*pb.Status, error) {
	val := new(big.Int).SetBytes(in.X)
	r := new(big.Int).SetBytes(in.R)
	
	valid := s.receiver.CheckDecommitment(r, val)
   		
	return &pb.Status{Success: valid}, nil
}




