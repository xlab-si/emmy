package tests

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"testing"
)

var testGrpcServerEndpont = "localhost:7008"

func setupTestGrpcServer() *grpc.Server {
	lis, err := net.Listen("tcp", ":7008")
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}
	testGrpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(math.MaxUint32),
	)
	pb.RegisterProtocolServer(testGrpcServer, server.NewProtocolServer())
	go testGrpcServer.Serve(lis)
	return testGrpcServer
}

func teardownTestGrpcServer(server *grpc.Server) {
	server.GracefulStop()
}

func TestMain(m *testing.M) {
	server := setupTestGrpcServer()
	returnCode := m.Run()
	teardownTestGrpcServer(server)
	os.Exit(returnCode)
}

func testPedersen(n *big.Int) error {
	dlog := config.LoadDLog("pedersen")
	c, err := client.NewPedersenClient(testGrpcServerEndpont, pb.SchemaVariant_SIGMA, dlog, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func testPedersenEC(n *big.Int) error {
	c, err := client.NewPedersenECClient(testGrpcServerEndpont, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func testSchnorr(n *big.Int, variant pb.SchemaVariant) error {
	dlog := config.LoadDLog("schnorr")
	c, err := client.NewSchnorrClient(testGrpcServerEndpont, variant, dlog, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func testSchnorrEC(n *big.Int, variant pb.SchemaVariant) error {
	c, err := client.NewSchnorrECClient(testGrpcServerEndpont, variant, dlog.P256, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func TestGRPC_Commitments(t *testing.T) {
	commitVal := big.NewInt(121212121)

	assert.Nil(t, testPedersen(commitVal), "should finish without errors")
	assert.Nil(t, testPedersenEC(commitVal), "should finish without errors")
}

func TestGRPC_Dlogproofs(t *testing.T) {
	n := big.NewInt(345345345334)
	desc := "should finish without errors"

	assert.Nil(t, testSchnorr(n, pb.SchemaVariant_SIGMA), desc)
	assert.Nil(t, testSchnorr(n, pb.SchemaVariant_ZKP), desc)
	assert.Nil(t, testSchnorr(n, pb.SchemaVariant_ZKPOK), desc)
	assert.Nil(t, testSchnorrEC(n, pb.SchemaVariant_SIGMA), desc)
	assert.Nil(t, testSchnorrEC(n, pb.SchemaVariant_ZKP), desc)
	assert.Nil(t, testSchnorrEC(n, pb.SchemaVariant_ZKPOK), desc)
}

func testCSPaillier(m, l *big.Int, pubKeyPath string) error {
	c, err := client.NewCSPaillierClient(testGrpcServerEndpont, pubKeyPath, m, l)
	if err != nil {
		return err
	}
	return c.Run()
}

func TestGRPC_Encryption(t *testing.T) {
	m := common.GetRandomInt(big.NewInt(8685849))
	l := common.GetRandomInt(big.NewInt(340002223232))

	assert.NotNil(t, testCSPaillier(m, l, "testdata/cspaillierpubkey.txt"), "should finish with error")
}
