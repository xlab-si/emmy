package tests

import (
	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/client"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
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

func runTestGrpcClient(schemaType pb.SchemaType, schemaVariant pb.SchemaVariant,
	protocolParams client.ProtocolParams) error {
	c, err := client.NewProtocolClient(testGrpcServerEndpont, schemaType, schemaVariant)
	if err != nil {
		return err
	}
	c.ExecuteProtocol(protocolParams)
	return nil
}

func TestClient_WithInvalidSchemaType(t *testing.T) {
	err := runTestGrpcClient(pb.SchemaType_PEDERSEN, 999, nil)
	assert.NotNil(t, err, "invalid schema type should return an error")
}

func TestClient_WithInvalidSchemaVariant(t *testing.T) {
	err := runTestGrpcClient(999, pb.SchemaVariant_SIGMA, nil)
	assert.NotNil(t, err, "invalid schema variant should return an error")
}

func TestGRPC_Dlogproofs(t *testing.T) {
	pp := client.ProtocolParams{"secret": big.NewInt(345345345334)}

	schemaTypes := []pb.SchemaType{
		pb.SchemaType_SCHNORR,
		pb.SchemaType_SCHNORR,
		pb.SchemaType_SCHNORR,
		pb.SchemaType_SCHNORR_EC,
		pb.SchemaType_SCHNORR_EC,
		pb.SchemaType_SCHNORR_EC,
	}
	schemaVariants := []pb.SchemaVariant{
		pb.SchemaVariant_SIGMA,
		pb.SchemaVariant_ZKP,
		pb.SchemaVariant_ZKPOK,
		pb.SchemaVariant_SIGMA,
		pb.SchemaVariant_ZKP,
		pb.SchemaVariant_ZKPOK,
	}

	for i := range schemaTypes {
		err := runTestGrpcClient(schemaTypes[i], schemaVariants[i], pp)
		assert.Nil(t, err, "should finish without errors")
	}
}

func TestGRPC_Commitments(t *testing.T) {
	pp := client.ProtocolParams{"commitVal": big.NewInt(121212121)}

	schemaTypes := []pb.SchemaType{
		pb.SchemaType_PEDERSEN,
		pb.SchemaType_PEDERSEN_EC,
	}

	for _, schemaType := range schemaTypes {
		err := runTestGrpcClient(schemaType, pb.SchemaVariant_SIGMA, pp)
		assert.Nil(t, err, "should finish without errors")
	}
}

func TestGRPC_Encryption(t *testing.T) {
	pp := client.ProtocolParams{
		"m":     common.GetRandomInt(big.NewInt(8685849)),
		"label": common.GetRandomInt(big.NewInt(340002223232)),
	}
	err := runTestGrpcClient(pb.SchemaType_CSPAILLIER, pb.SchemaVariant_SIGMA, pp)
	assert.Nil(t, err, "should finish without errors")
}
