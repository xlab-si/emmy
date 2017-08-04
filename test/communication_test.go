package test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
	"math/big"
	"os"
	"testing"
)

var testGrpcServerEndpont = "localhost:7008"

// testGrpcClientConn is re-used for all the test clients
var testGrpcClientConn *grpc.ClientConn

// TestMain is run implicitly and only once, before any of the tests defined in this file run.
// It sets up a test gRPC server and establishes connection to the server. This gRPC client
// connection is then re-used in all the tests to reduce overhead.
// Once all the tests run, we close the connection to the server and stop the server.
func TestMain(m *testing.M) {
	// Prevent logs emmitted from emmy packages as they affect performance
	log.TurnOff()

	// Instantiate emmy server and start it in a seperate goroutine
	server := server.NewProtocolServer()
	go server.Start(7008)

	// Establish a connection to previously started server
	testGrpcClientConn, _ = client.GetConnection(testGrpcServerEndpont)

	// At this point all the tests will actually run
	returnCode := m.Run()

	// Cleanup - close connection, stop the server and exit
	server.Teardown()
	testGrpcClientConn.Close()

	os.Exit(returnCode)
}

func TestGRPC_Commitments(t *testing.T) {
	commitVal := big.NewInt(121212121)

	assert.Nil(t, Pedersen(testGrpcClientConn, commitVal), "should finish without errors")
	assert.Nil(t, PedersenEC(testGrpcClientConn, commitVal), "should finish without errors")
}

func TestGRPC_Dlogproofs(t *testing.T) {
	n := big.NewInt(345345345334)
	desc := "should finish without errors"

	assert.Nil(t, Schnorr(testGrpcClientConn, n, pb.SchemaVariant_SIGMA), desc)
	assert.Nil(t, Schnorr(testGrpcClientConn, n, pb.SchemaVariant_ZKP), desc)
	assert.Nil(t, Schnorr(testGrpcClientConn, n, pb.SchemaVariant_ZKPOK), desc)
	assert.Nil(t, SchnorrEC(testGrpcClientConn, n, pb.SchemaVariant_SIGMA), desc)
	assert.Nil(t, SchnorrEC(testGrpcClientConn, n, pb.SchemaVariant_ZKP), desc)
	assert.Nil(t, SchnorrEC(testGrpcClientConn, n, pb.SchemaVariant_ZKPOK), desc)
}

func TestGRPC_Encryption(t *testing.T) {
	m := common.GetRandomInt(big.NewInt(8685849))
	l := common.GetRandomInt(big.NewInt(340002223232))

	assert.NotNil(t, CSPaillier(testGrpcClientConn, m, l, "testdata/cspaillierpubkey.txt"),
		"should finish with error")
}

func TestGRPC_Pseudonymsys(t *testing.T) {
	authenticated, err := Pseudonymsys(testGrpcClientConn)
	assert.Nil(t, err, fmt.Sprintf("Should finish without errors, got: %v", err))
	assert.Equal(t, authenticated, true, "Pseudonymsys test failed (user was not authenticated)")
}

func TestGRPC_PseudonymsysEC(t *testing.T) {
	authenticated, err := PseudonymsysEC(testGrpcClientConn)
	assert.Nil(t, err, fmt.Sprintf("Should finish without errors, got: %v", err))
	assert.Equal(t, authenticated, true, "PseudonymsysEC test failed (user was not authenticated)")
}
