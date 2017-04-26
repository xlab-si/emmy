package commitments

import (
	"fmt"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"math/big"
)

type PedersenECProtocolClient struct {
	client    *pb.PedersenECClient
	conn      *grpc.ClientConn
	committer *PedersenECCommitter
}

func NewPedersenECProtocolClient() *PedersenECProtocolClient {
	port := config.LoadServerPort()
	conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", port), grpc.WithInsecure())
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

func (client *PedersenECProtocolClient) Run(val *big.Int) (bool, error) {

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

type PedersenECProtocolServer struct {
	// server acts as an interface to the commitment receiver
	receiver *PedersenECReceiver
}

func NewPedersenECProtocolServer() *PedersenECProtocolServer {
	/* this is the root of the issues with parallel clients failing
	since the receiver's context is okay for one, but not other clients
	we have to introduce some sort of session handling, since we obviously need to maintain states*/
	receiver := NewPedersenECReceiver()
	protocolServer := PedersenECProtocolServer{
		receiver: receiver,
	}

	log.Printf("Instantiated new PedersenECProtocolServer")
	return &protocolServer
}

func (s *PedersenECProtocolServer) GetH(ctx context.Context,
	in *pb.EmptyMsg) (*pb.ECGroupElement, error) {
	h := s.receiver.GetH() // we could as well use s.receiver.h as h is defined in the same package and thus accessible from here
	log.Printf("[getH] Sending response: {X=%v, Y=%v}", h.X, h.Y)
	response := pb.ECGroupElement{X: h.X.Bytes(), Y: h.Y.Bytes()}
	return &response, nil
}

func (s *PedersenECProtocolServer) Commit(ctx context.Context,
	in *pb.ECGroupElement) (*pb.EmptyMsg, error) {
	el := common.ToECGroupElement(in)
	s.receiver.SetCommitment(el)
	log.Printf("[commit] Sending response")
	return &pb.EmptyMsg{}, nil
}

func (s *PedersenECProtocolServer) Decommit(ctx context.Context,
	in *pb.PedersenDecommitment) (*pb.Status, error) {
	val := new(big.Int).SetBytes(in.X)
	r := new(big.Int).SetBytes(in.R)

	valid := s.receiver.CheckDecommitment(r, val)
	log.Printf("[decommit] CheckDecommitment args: {r=%v, val=%v}", r, val)
	log.Printf("[decommit] Sending response: {valid=%v}", valid)
	return &pb.Status{Success: valid}, nil
}
