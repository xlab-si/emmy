package commitments

import (
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"math/big"
	"net"
)

type PedersenECProtocolClient struct {
	client    *pb.PedersenECClient
	conn      *grpc.ClientConn
	committer *PedersenECCommitter
}

func NewPedersenECProtocolClient() *PedersenECProtocolClient {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	client := pb.NewPedersenECClient(conn)
	committer := NewPedersenECCommitter()

	protocolClient := PedersenECProtocolClient{
		client:    &client,
		conn:      conn,
		committer: committer,
	}
	return &protocolClient
}

func (client *PedersenECProtocolClient) ObtainH() error {
	// ask commitment receiver for h:
	reply, err := (*client.client).GetH(context.Background(), &pb.EmptyMsg{})
	if err != nil {
		log.Fatalf("could not get h: %v", err)
	}

	el := common.ToECGroupElement(reply)
	(*client.committer).SetH(el)
	return nil
}

func (client *PedersenECProtocolClient) Commit(x *big.Int) (bool, error) {
	commitment, err := client.committer.GetCommitMsg(x)
	if err != nil {
		log.Fatalf("could not generate committment message: %v", err)
	}

	log.Println("committing..........")
	_, err = (*client.client).Commit(context.Background(), common.ToPbECGroupElement(commitment))
	if err != nil {
		log.Fatalf("could not commit: %v", err)
	}

	return true, err
}

func (client *PedersenECProtocolClient) Decommit() (bool, error) {
	val, r := client.committer.GetDecommitMsg()

	log.Println("decommitting..........")
	reply, err := (*client.client).Decommit(context.Background(), &pb.PedersenDecommitment{X: val.Bytes(), R: r.Bytes()})
	if err != nil {
		log.Fatalf("could not decommit: %v", err)
	}

	client.conn.Close()
	return reply.Success, err
}

type PedersenECProtocolServer struct {
	// server acts as an interface to the commitment receiver
	receiver *PedersenECReceiver
}

func NewPedersenECProtocolServer() *PedersenECProtocolServer {
	receiver := NewPedersenECReceiver()
	protocolServer := PedersenECProtocolServer{
		receiver: receiver,
	}

	return &protocolServer
}

func (server *PedersenECProtocolServer) Listen() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	pb.RegisterPedersenECServer(s, server)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (s *PedersenECProtocolServer) GetH(ctx context.Context,
	in *pb.EmptyMsg) (*pb.ECGroupElement, error) {
	h := s.receiver.GetH() // we could as well use s.receiver.h as h is defined in the same package and thus accessible from here
	return &pb.ECGroupElement{X: h.X.Bytes(), Y: h.Y.Bytes()}, nil
}

func (s *PedersenECProtocolServer) Commit(ctx context.Context,
	in *pb.ECGroupElement) (*pb.EmptyMsg, error) {
	el := common.ToECGroupElement(in)
	s.receiver.SetCommitment(el)

	return &pb.EmptyMsg{}, nil
}

func (s *PedersenECProtocolServer) Decommit(ctx context.Context,
	in *pb.PedersenDecommitment) (*pb.Status, error) {
	val := new(big.Int).SetBytes(in.X)
	r := new(big.Int).SetBytes(in.R)

	valid := s.receiver.CheckDecommitment(r, val)

	return &pb.Status{Success: valid}, nil
}
