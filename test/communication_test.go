package tests

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/errors"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
	"log"
	"math"
	"math/big"
	"net"
	"os"
	"testing"
)

var testGrpcServer *grpc.Server
var testGrpcServerEndpont = "localhost:7008"

func setupTestGrpcServer() {

	lis, err := net.Listen("tcp", ":7008")
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}
	testGrpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(math.MaxUint32),
	)
	pb.RegisterProtocolServer(testGrpcServer, server.NewProtocolServer())
	go testGrpcServer.Serve(lis)
}

func teardownTestGrpcServer() {
	testGrpcServer.Stop()
}

func runTestGrpcClient(clientParams *client.ClientParams, protocolParams client.ProtocolParams) error {
	c, err := client.NewProtocolClient(testGrpcServerEndpont, clientParams)
	if err != nil {
		return err
	}
	c.ExecuteProtocol(protocolParams)
	return nil
}

func TestMain(m *testing.M) {
	setupTestGrpcServer()
	returnCode := m.Run()
	//teardownTestGrpcServer()
	os.Exit(returnCode)
}

func TestClient_WithMissingSchemaType(t *testing.T) {
	cp := &client.ClientParams{}
	err := runTestGrpcClient(cp, nil)
	assert.NotNil(t, err, "missing schema type should return an error")
	assert.IsType(t, errors.ErrInvalidSchema, err, "should return an error type")
}

func TestClient_WithInvalidSchemaType(t *testing.T) {
	cp := &client.ClientParams{SchemaType: "PEDERSEN", SchemaVariant: "something nonexistent"}
	err := runTestGrpcClient(cp, nil)
	assert.NotNil(t, err, "invalid schema type should return an error")
	assert.IsType(t, errors.ErrInvalidSchema, err, "should return an error type")
}

func TestClient_WithMissingSchemaVariant(t *testing.T) {
	cp := &client.ClientParams{SchemaType: "PEDERSEN"}
	err := runTestGrpcClient(cp, nil)
	assert.Nil(t, err, "missing schema variant should not return an error, but set a default")
}

func TestClient_WithInvalidSchemaVariant(t *testing.T) {
	cp := &client.ClientParams{SchemaType: "somethingInvalid", SchemaVariant: "SIGMA"}
	err := runTestGrpcClient(cp, nil)
	assert.NotNil(t, err, "invalid schema variant should return an error")
	assert.IsType(t, errors.ErrInvalidVariant, err, "should return an error type")
}

func TestGRPC_Dlogproofs(t *testing.T) {
	pp := client.ProtocolParams{"secret": *big.NewInt(345345345334)}

	cps := []*client.ClientParams{
		{SchemaType: "SCHNORR"},
		{SchemaType: "SCHNORR", SchemaVariant: "ZKP"},
		{SchemaType: "SCHNORR", SchemaVariant: "ZKPOK"},
		{SchemaType: "SCHNORR_EC", SchemaVariant: "SIGMA"},
		{SchemaType: "SCHNORR_EC", SchemaVariant: "ZKP"},
		{SchemaType: "SCHNORR_EC", SchemaVariant: "ZKPOK"},
	}

	for _, cp := range cps {
		err := runTestGrpcClient(cp, pp)
		assert.Nil(t, err, "should finish without errors")
		//assert.Equal(t, true, "should finish with status = sucess, but failed")
	}
}

func TestGRPC_Commitments(t *testing.T) {
	pp := client.ProtocolParams{"secret": *big.NewInt(121212121)}

	cps := []*client.ClientParams{
		{SchemaType: "PEDERSEN"},
		{SchemaType: "PEDERSEN_EC"},
	}

	for _, cp := range cps {
		err := runTestGrpcClient(cp, pp)
		assert.Nil(t, err, "should finish without errors")
		//assert.Equal(t, true, "should finish with status = sucess, but failed")
	}

}
