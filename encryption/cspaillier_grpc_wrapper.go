package encryption

import (
	"errors"
	pb "github.com/xlab-si/emmy/comm/pro"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"log"
	"math/big"
	"net"
)

type CSPaillierProtocolClient struct {
	client    *pb.CSPaillierProtocolClient
	conn      *grpc.ClientConn
	encryptor *CSPaillier
}

func NewCSPaillierProtocolClient(pubPath string) (*CSPaillierProtocolClient, error) {
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		return nil, errors.New("could not connect")
	}

	client := pb.NewCSPaillierProtocolClient(conn)

	encryptor, _ := NewCSPaillierFromPubKeyFile(pubPath)

	protocolClient := CSPaillierProtocolClient{
		client:    &client,
		conn:      conn,
		encryptor: encryptor,
	}
	return &protocolClient, nil
}

func (client *CSPaillierProtocolClient) OpeningMsg(m, u, e, v, label *big.Int) error {
	l, delta := client.encryptor.GetOpeningMsg(m)
	msg := &pb.CSPaillierOpening{U: u.Bytes(), E: e.Bytes(), V: v.Bytes(), Delta: delta.Bytes(),
		Label: label.Bytes(), L: l.Bytes()}

	_, err := (*client.client).OpeningMsg(context.Background(), msg)
	if err != nil {
		return err
	}
	return nil
}

func (client *CSPaillierProtocolClient) ProofRandomData(u, e, label *big.Int) (*big.Int, error) {
	u1, e1, v1, delta1, l1, err := client.encryptor.GetProofRandomData(u, e, label)
	if err != nil {
		log.Fatalf("Generating CSPaillier second message failed")
	}

	msg := &pb.CSPaillierProofRandomData{U1: u1.Bytes(), E1: e1.Bytes(), V1: v1.Bytes(),
		Delta1: delta1.Bytes(), L1: l1.Bytes()}
	reply, err := (*client.client).ProofRandomData(context.Background(), msg) // contains challenge
	challenge := new(big.Int).SetBytes(reply.X1)
	return challenge, nil
}

func (client *CSPaillierProtocolClient) ProofData(c *big.Int) (bool, error) {
	rTilde, sTilde, mTilde := client.encryptor.GetProofData(c)

	rTildeIsNeg := false
	sTildeIsNeg := false
	mTildeIsNeg := false

	if rTilde.Cmp(big.NewInt(0)) < 0 {
		rTildeIsNeg = true
	}
	if sTilde.Cmp(big.NewInt(0)) < 0 {
		sTildeIsNeg = true
	}
	if mTilde.Cmp(big.NewInt(0)) < 0 {
		mTildeIsNeg = true
	}

	msg := &pb.CSPaillierProofData{RTilde: rTilde.Bytes(), RTildeIsNeg: rTildeIsNeg,
		STilde: sTilde.Bytes(), STildeIsNeg: sTildeIsNeg,
		MTilde: mTilde.Bytes(), MTildeIsNeg: mTildeIsNeg}
	status, err := (*client.client).ProofData(context.Background(), msg)
	if err != nil {
		return false, err
	}
	return status.Success, nil
}

// Encrypts m, computes delta = gamma^m and proves that (u, e, v) is encryption of log_gamma(delta).
func (client *CSPaillierProtocolClient) Run(m, label *big.Int) (bool, error) {

	u, e, v, _ := client.encryptor.Encrypt(m, label)

	err := client.OpeningMsg(m, u, e, v, label)
	if err != nil {
		log.Fatalf("first CS Paillier message failed")
	}

	challenge, err := client.ProofRandomData(u, e, label)
	if err != nil {
		log.Fatalf("second CS Paillier message failed")
	}

	isProved, err := client.ProofData(challenge)
	if err != nil {
		log.Fatalf("failed to retrieve second msg")
	}
	return isProved, err
}

type CSPaillierProtocolServer struct {
	decryptor *CSPaillier
}

func NewCSPaillierProtocolServer(secKeyPath string) (*CSPaillierProtocolServer, error) {
	decryptor, err := NewCSPaillierFromSecKey(secKeyPath)
	if err != nil {
		return nil, err
	}
	protocolServer := CSPaillierProtocolServer{
		decryptor: decryptor,
	}
	return &protocolServer, nil
}

func (s *CSPaillierProtocolServer) OpeningMsg(ctx context.Context,
	in *pb.CSPaillierOpening) (*pb.EmptyMsg, error) {
	u := new(big.Int).SetBytes(in.U)
	e := new(big.Int).SetBytes(in.E)
	v := new(big.Int).SetBytes(in.V)
	delta := new(big.Int).SetBytes(in.Delta)
	label := new(big.Int).SetBytes(in.Label)
	l := new(big.Int).SetBytes(in.L)

	s.decryptor.SetVerifierEncData(u, e, v, delta, label, l)

	return &pb.EmptyMsg{}, nil
}

func (s *CSPaillierProtocolServer) ProofRandomData(ctx context.Context,
	in *pb.CSPaillierProofRandomData) (*pb.BigInt, error) {
	u1 := new(big.Int).SetBytes(in.U1)
	e1 := new(big.Int).SetBytes(in.E1)
	v1 := new(big.Int).SetBytes(in.V1)
	delta1 := new(big.Int).SetBytes(in.Delta1)
	l1 := new(big.Int).SetBytes(in.L1)

	c := s.decryptor.GetChallenge()
	s.decryptor.SetProofRandomData(u1, e1, v1, delta1, l1, c)

	return &pb.BigInt{X1: c.Bytes()}, nil
}

func (s *CSPaillierProtocolServer) ProofData(ctx context.Context,
	in *pb.CSPaillierProofData) (*pb.Status, error) {
	rTilde := new(big.Int).SetBytes(in.RTilde)
	if in.RTildeIsNeg {
		rTilde = new(big.Int).Neg(rTilde)
	}

	sTilde := new(big.Int).SetBytes(in.STilde)
	if in.STildeIsNeg {
		sTilde = new(big.Int).Neg(sTilde)
	}

	mTilde := new(big.Int).SetBytes(in.MTilde)
	if in.MTildeIsNeg {
		mTilde = new(big.Int).Neg(mTilde)
	}

	isOk := s.decryptor.Verify(rTilde, sTilde, mTilde)

	return &pb.Status{Success: isOk}, nil
}

func (server *CSPaillierProtocolServer) Listen() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()

	pb.RegisterCSPaillierProtocolServer(s, server)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
