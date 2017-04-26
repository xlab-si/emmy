package commitments

import (
	"fmt"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/config"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"math/big"
)

type PedersenProtocolClient struct {
	client    *pb.PedersenClient
	conn      *grpc.ClientConn
	committer *PedersenCommitter
}

func NewPedersenProtocolClient() *PedersenProtocolClient {
	port := config.LoadServerPort()
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", port), grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	client := pb.NewPedersenClient(conn)
	committer := NewPedersenCommitter()

	protocolClient := PedersenProtocolClient{
		client:    &client,
		conn:      conn,
		committer: committer,
	}
	return &protocolClient
}

func (client *PedersenProtocolClient) ObtainH() error {
	// ask commitment receiver for h:
	reply, err := (*client.client).GetH(context.Background(), &pb.EmptyMsg{})
	if err != nil {
		log.Fatalf("could not get h: %v", err)
	}

	p := new(big.Int).SetBytes(reply.P)
	q := new(big.Int).SetBytes(reply.OrderOfSubgroup)
	g := new(big.Int).SetBytes(reply.G)
	(*client.committer).SetGroup(p, q, g)

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

func (client *PedersenProtocolClient) Run(val *big.Int) (bool, error) {
	err := client.ObtainH()

	if err != nil {
		log.Fatalf("Getting H not successful: %v", err)
	}

	success, err := client.Commit(val) // TODO: this should return only err
	if err != nil {
		log.Fatalf("Commit not successful: %v", err)
	}

	success, err = client.Decommit()
	if err != nil {
		log.Fatalf("Decommit not successful: %v", err)
	}

	return success, err
}

type PedersenProtocolServer struct {
	receiver *PedersenReceiver
}

func NewPedersenProtocolServer() *PedersenProtocolServer {
	receiver := NewPedersenReceiver()
	protocolServer := PedersenProtocolServer{
		receiver: receiver,
	}

	return &protocolServer
}

func (s *PedersenProtocolServer) GetH(ctx context.Context,
	in *pb.EmptyMsg) (*pb.PedersenFirst, error) {
	h := s.receiver.GetH() // we could as well use s.receiver.h as h is defined in the same package and thus accessible from here
	group := s.receiver.GetGroup()

	return &pb.PedersenFirst{H: h.Bytes(), P: group.P.Bytes(),
		OrderOfSubgroup: group.OrderOfSubgroup.Bytes(), G: group.G.Bytes()}, nil
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
