package server

import (
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
	"io"
	"math"
	"net"
	"net/http"
	"path/filepath"
)

var _ pb.ProtocolServer = (*Server)(nil)

type Server struct {
	grpcServer *grpc.Server
}

var logger = log.ServerLogger

// NewProtocolServer initializes an instance of the Server struct and returns a pointer.
// It performs some default configuration (tracing of gRPC communication and interceptors)
// and registers RPC protocol server with gRPC server.
func NewProtocolServer() *Server {
	logger.Info("Instantiating new protocol server")

	// Register our generic service
	logger.Info("Registering services")

	// Allow as much concurrent streams as possible and register a gRPC stream interceptor
	// for logging and monitoring purposes.
	server := &Server{
		grpcServer: grpc.NewServer(
			grpc.MaxConcurrentStreams(math.MaxUint32),
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		),
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via Server's EnableTracing function.
	grpc.EnableTracing = false

	// Register our protocol server with the supporting gRPC server
	pb.RegisterProtocolServer(server.grpcServer, server)

	// Initialize gRPC metrics offered by Prometheus package
	grpc_prometheus.Register(server.grpcServer)

	return server
}

// Start configures and starts the protocol server at the requested port.
func (s *Server) Start(port int) {
	connStr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		logger.Criticalf("Could not connect: %v", err)
	}

	// Register Prometheus metrics handler and serve metrics page on the desired endpoint.
	// Metrics are handled via HTTP in a separate goroutine as gRPC requests,
	// as grpc server's performance over HTTP (grpcServer.ServeHTTP) is much worse.
	http.Handle("/metrics", prometheus.Handler())

	// After this, /metrics will be available, along with /debug/requests, /debug/events in
	// case server's EnableTracing function is called.
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	logger.Infof("Emmy server listening for connections on port %d", port)
	s.grpcServer.Serve(listener)
}

// Teardown stops the protocol server by gracefully stopping enclosed gRPC server.
func (s *Server) Teardown() {
	s.grpcServer.GracefulStop()
}

// EnableTracing instructs the gRPC framework to enable its tracing capability, which
// is mainly used for debugging purposes.
// Although this function does not explicitly affect the Server struct, it is wired to Server
// in order to provide a nicer API when setting up the server.
func (s *Server) EnableTracing() {
	grpc.EnableTracing = true
	logger.Infof("Enabled gRPC tracing")
}

func (s *Server) send(msg *pb.Message, stream pb.Protocol_RunServer) error {
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("Error sending message:", err)
	}
	logger.Info("Successfully sent response:", msg)

	return nil
}

func (s *Server) receive(stream pb.Protocol_RunServer) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("An error ocurred: %v", err)
	}
	logger.Info("Received request from the stream", resp)
	return resp, nil
}

func (s *Server) Run(stream pb.Protocol_RunServer) error {
	logger.Info("Starting new RPC")

	req, err := s.receive(stream)
	if err != nil {
		return err
	}

	reqClientId := req.ClientId
	reqSchemaType := req.Schema
	reqSchemaVariant := req.SchemaVariant

	// Check whether the client requested a valid schema
	reqSchemaTypeStr, schemaValid := pb.SchemaType_name[int32(reqSchemaType)]
	if !schemaValid {
		return fmt.Errorf("Client [", reqClientId, "] requested invalid schema: %v", reqSchemaType)
	}

	// Check whether the client requested a valid schema variant
	reqSchemaVariantStr, variantValid := pb.SchemaVariant_name[int32(reqSchemaVariant)]
	if !variantValid {
		return fmt.Errorf("Client [ %v ] requested invalid schema variant: %v", reqClientId, reqSchemaVariant)
	}

	logger.Noticef("Client [ %v ] requested schema %v, variant %v", reqClientId, reqSchemaTypeStr, reqSchemaVariantStr)

	// Convert Sigma, ZKP or ZKPOK protocol type to a common type
	protocolType := common.ToProtocolType(reqSchemaVariant)

	switch reqSchemaType {
	case pb.SchemaType_PEDERSEN_EC:
		err = s.PedersenEC(stream)
	case pb.SchemaType_PEDERSEN:
		dlog := config.LoadDLog("pedersen")
		err = s.Pedersen(dlog, stream)
	case pb.SchemaType_SCHNORR:
		dlog := config.LoadDLog("schnorr")
		err = s.Schnorr(req, dlog, protocolType, stream)
	case pb.SchemaType_SCHNORR_EC:
		err = s.SchnorrEC(req, protocolType, stream)
	case pb.SchemaType_CSPAILLIER:
		keyDir := config.LoadKeyDirFromConfig()
		secKeyPath := filepath.Join(keyDir, "cspaillierseckey.txt")
		err = s.CSPaillier(req, secKeyPath, stream)
	case pb.SchemaType_PSEUDONYMSYS_CA:
		err = s.PseudonymsysCA(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_NYM_GEN:
		err = s.PseudonymsysGenerateNym(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_ISSUE_CREDENTIAL:
		err = s.PseudonymsysIssueCredential(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_TRANSFER_CREDENTIAL:
		err = s.PseudonymsysTransferCredential(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_CA_EC:
		err = s.PseudonymsysCAEC(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_NYM_GEN_EC:
		err = s.PseudonymsysGenerateNymEC(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_ISSUE_CREDENTIAL_EC:
		err = s.PseudonymsysIssueCredentialEC(req, stream)
	case pb.SchemaType_PSEUDONYMSYS_TRANSFER_CREDENTIAL_EC:
		err = s.PseudonymsysTransferCredentialEC(req, stream)
	}

	if err != nil {
		logger.Notice("Closing RPC due to previous errors")
		return fmt.Errorf("FAIL: %v", err)
	}

	logger.Info("RPC finished successfully")
	return nil
}
