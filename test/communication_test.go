package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
	"math/big"
	"os"
	"testing"
)

var testGrpcServerEndpoint = "localhost:7008"

// testGrpcClientConn is re-used for all the test clients
var testGrpcClientConn *grpc.ClientConn

// TestMain is run implicitly and only once, before any of the tests defined in this file run.
// It sets up a test gRPC server and establishes connection to the server. This gRPC client
// connection is then re-used in all the tests to reduce overhead.
// Once all the tests run, we close the connection to the server and stop the server.
func TestMain(m *testing.M) {
	// Set debug log level for easier troubleshooting in case something goes wrong
	client.SetLogLevel("debug")
	server.SetLogLevel("debug")

	server, err := server.NewProtocolServer("testdata/server.pem", "testdata/server.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	go server.Start(7008)

	// Establish a connection to previously started server
	testGrpcClientConn, err = client.GetConnection(testGrpcServerEndpoint,
		"testdata/server.pem", false)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// At this point all the tests will actually run
	returnCode := m.Run()

	// Cleanup - close connection, stop the server and exit
	server.Teardown()
	testGrpcClientConn.Close()
	os.Exit(returnCode)
}

func testPedersen(n *big.Int) error {
	dlog := config.LoadDLog("pedersen")
	c, err := client.NewPedersenClient(testGrpcClientConn, pb.SchemaVariant_SIGMA, dlog, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func testPedersenEC(n *big.Int) error {
	c, err := client.NewPedersenECClient(testGrpcClientConn, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func testSchnorr(n *big.Int, variant pb.SchemaVariant) error {
	dlog := config.LoadDLog("schnorr")
	c, err := client.NewSchnorrClient(testGrpcClientConn, variant, dlog, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func testSchnorrEC(n *big.Int, variant pb.SchemaVariant) error {
	c, err := client.NewSchnorrECClient(testGrpcClientConn, variant, dlog.P256, n)
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
	c, err := client.NewCSPaillierClient(testGrpcClientConn, pubKeyPath, m, l)
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
