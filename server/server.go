/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package server

import (
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"math"
	"net"
	"net/http"
	"path/filepath"
)

var _ pb.ProtocolServer = (*Server)(nil)

type Server struct {
	grpcServer *grpc.Server
	logger     log.Logger
	*sessionManager
}

// NewProtocolServer initializes an instance of the Server struct and returns a pointer.
// It performs some default configuration (tracing of gRPC communication and interceptors)
// and registers RPC protocol server with gRPC server. It requires TLS cert and keyfile
// in order to establish a secure channel with clients.
func NewProtocolServer(certFile, keyFile string, logger log.Logger) (*Server, error) {
	logger.Info("Instantiating new protocol server")

	// Register our generic service
	logger.Info("Registering services")

	// Obtain TLS credentials
	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	logger.Infof("Successfully read certificate [%s] and key [%s]", certFile, keyFile)

	sessionManager, err := newSessionManager(config.LoadSessionKeyMinByteLen())
	if err != nil {
		logger.Warning(err)
	}

	// Allow as much concurrent streams as possible and register a gRPC stream interceptor
	// for logging and monitoring purposes.
	server := &Server{
		grpcServer: grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxConcurrentStreams(math.MaxUint32),
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		),
		logger:         logger,
		sessionManager: sessionManager,
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via Server's EnableTracing function.
	grpc.EnableTracing = false

	// Register our services with the supporting gRPC server
	pb.RegisterProtocolServer(server.grpcServer, server)
	pb.RegisterInfoServer(server.grpcServer, server)

	// Initialize gRPC metrics offered by Prometheus package
	grpc_prometheus.Register(server.grpcServer)

	logger.Notice("gRPC Services registered")
	return server, nil
}

// Start configures and starts the protocol server at the requested port.
func (s *Server) Start(port int) error {
	connStr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		return fmt.Errorf("Could not connect: %v", err)
	}

	// Register Prometheus metrics handler and serve metrics page on the desired endpoint.
	// Metrics are handled via HTTP in a separate goroutine as gRPC requests,
	// as grpc server's performance over HTTP (grpcServer.ServeHTTP) is much worse.
	http.Handle("/metrics", prometheus.Handler())

	// After this, /metrics will be available, along with /debug/requests, /debug/events in
	// case server's EnableTracing function is called.
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	s.logger.Noticef("Emmy server listening for connections on port %d", port)
	s.grpcServer.Serve(listener)
	return nil
}

// Teardown stops the protocol server by gracefully stopping enclosed gRPC server.
func (s *Server) Teardown() {
	s.logger.Notice("Tearing down gRPC server")
	s.grpcServer.GracefulStop()
}

// EnableTracing instructs the gRPC framework to enable its tracing capability, which
// is mainly used for debugging purposes.
// Although this function does not explicitly affect the Server struct, it is wired to Server
// in order to provide a nicer API when setting up the server.
func (s *Server) EnableTracing() {
	grpc.EnableTracing = true
	s.logger.Notice("Enabled gRPC tracing")
}

func (s *Server) send(msg *pb.Message, stream pb.Protocol_RunServer) error {
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("Error sending message:", err)
	}
	s.logger.Infof("Successfully sent response of type %T", msg.Content)
	s.logger.Debugf("%+v", msg)

	return nil
}

func (s *Server) receive(stream pb.Protocol_RunServer) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("An error ocurred: %v", err)
	}
	s.logger.Infof("Received request of type %T from the stream", resp.Content)
	s.logger.Debugf("%+v", resp)

	return resp, nil
}

func (s *Server) Run(stream pb.Protocol_RunServer) error {
	s.logger.Info("Starting new RPC")

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

	s.logger.Noticef("Client [ %v ] requested schema %v, variant %v", reqClientId, reqSchemaTypeStr, reqSchemaVariantStr)

	// Convert Sigma, ZKP or ZKPOK protocol type to a types type
	protocolType := types.ToProtocolType(reqSchemaVariant)
	// This curve will be used for all schemes
	curve := groups.P256

	switch reqSchemaType {
	case pb.SchemaType_PEDERSEN_EC:
		err = s.PedersenEC(curve, stream)
	case pb.SchemaType_PEDERSEN:
		group := config.LoadGroup("pedersen")
		err = s.Pedersen(group, stream)
	case pb.SchemaType_SCHNORR:
		group := config.LoadGroup("schnorr")
		err = s.Schnorr(req, group, protocolType, stream)
	case pb.SchemaType_SCHNORR_EC:
		err = s.SchnorrEC(req, protocolType, stream, curve)
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
		err = s.PseudonymsysCAEC(curve, req, stream)
	case pb.SchemaType_PSEUDONYMSYS_NYM_GEN_EC:
		err = s.PseudonymsysGenerateNymEC(curve, req, stream)
	case pb.SchemaType_PSEUDONYMSYS_ISSUE_CREDENTIAL_EC:
		err = s.PseudonymsysIssueCredentialEC(curve, req, stream)
	case pb.SchemaType_PSEUDONYMSYS_TRANSFER_CREDENTIAL_EC:
		err = s.PseudonymsysTransferCredentialEC(curve, req, stream)
	case pb.SchemaType_QR:
		group := config.LoadGroup("pseudonymsys")
		err = s.QR(req, group, stream)
	case pb.SchemaType_QNR:
		qr := config.LoadQR("qrsmall") // only for testing
		err = s.QNR(req, qr, stream)
	}

	if err != nil {
		s.logger.Error("Closing RPC due to previous errors")
		return fmt.Errorf("FAIL: %v", err)
	}

	s.logger.Notice("RPC finished successfully")
	return nil
}
