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
	"io"
	"math"
	"net"

	"net/http"
	"path/filepath"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// Curve to be used in all schemes using elliptic curve arithmetic.
	curve = groups.P256
)

// EmmyServer is an interface composed of all the auto-generated server interfaces that
// declare gRPC handler functions for emmy protocols and schemes.
type EmmyServer interface {
	pb.ProtocolServer
	pb.PseudonymSystemServer
	pb.PseudonymSystemCAServer
	pb.InfoServer
}

// Server struct implements the EmmyServer interface.
var _ EmmyServer = (*Server)(nil)

type Server struct {
	grpcServer *grpc.Server
	logger     log.Logger
	*sessionManager
	*registrationManager
}

// NewServer initializes an instance of the Server struct and returns a pointer.
// It performs some default configuration (tracing of gRPC communication and interceptors)
// and registers RPC server handlers with gRPC server. It requires TLS cert and keyfile
// in order to establish a secure channel with clients.
func NewServer(certFile, keyFile, dbAddress string, logger log.Logger) (*Server, error) {
	logger.Info("Instantiating new server")

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

	registrationManager, err := NewRegistrationManager(dbAddress)
	if err != nil {
		logger.Critical(err)
		return nil, err
	}

	// Allow as much concurrent streams as possible and register a gRPC stream interceptor
	// for logging and monitoring purposes.
	server := &Server{
		grpcServer: grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxConcurrentStreams(math.MaxUint32),
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		),
		logger:              logger,
		sessionManager:      sessionManager,
		registrationManager: registrationManager,
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via Server's EnableTracing function.
	grpc.EnableTracing = false

	// Register our services with the supporting gRPC server
	server.registerServices()

	// Initialize gRPC metrics offered by Prometheus package
	grpc_prometheus.Register(server.grpcServer)

	return server, nil
}

// Start configures and starts the protocol server at the requested port.
func (s *Server) Start(port int) error {
	connStr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		return fmt.Errorf("could not connect: %v", err)
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

// registerServices binds gRPC server interfaces to the server instance itself, as the server
// provides implementations of these interfaces.
func (s *Server) registerServices() {
	pb.RegisterProtocolServer(s.grpcServer, s)
	pb.RegisterInfoServer(s.grpcServer, s)
	pb.RegisterPseudonymSystemServer(s.grpcServer, s)
	pb.RegisterPseudonymSystemCAServer(s.grpcServer, s)

	s.logger.Notice("Registered gRPC Services")
}

func (s *Server) send(msg *pb.Message, stream pb.ServerStream) error {
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}
	if msg.ProtocolError != "" {
		s.logger.Infof("Successfully sent response of type %T", msg.ProtocolError)
	} else {
		s.logger.Infof("Successfully sent response of type %T", msg.Content)
	}
	s.logger.Debugf("%+v", msg)

	return nil
}

func (s *Server) receive(stream pb.ServerStream) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("an error ocurred: %v", err)
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
		return fmt.Errorf("client [ %d ] requested invalid schema: %v", reqClientId, reqSchemaType)
	}

	// Check whether the client requested a valid schema variant
	reqSchemaVariantStr, variantValid := pb.SchemaVariant_name[int32(reqSchemaVariant)]
	if !variantValid {
		return fmt.Errorf("client [ %d ] requested invalid schema variant: %v", reqClientId, reqSchemaVariant)
	}

	s.logger.Noticef("Client [ %v ] requested schema %v, variant %v", reqClientId, reqSchemaTypeStr, reqSchemaVariantStr)

	// Convert Sigma, ZKP or ZKPOK protocol type to a types type
	protocolType := reqSchemaVariant.GetNativeType()

	switch reqSchemaType {
	case pb.SchemaType_PEDERSEN_EC:
		err = s.PedersenEC(curve, stream)
	case pb.SchemaType_PEDERSEN:
		group := config.LoadSchnorrGroup()
		err = s.Pedersen(group, stream)
	case pb.SchemaType_SCHNORR:
		group := config.LoadSchnorrGroup()
		err = s.Schnorr(req, group, protocolType, stream)
	case pb.SchemaType_SCHNORR_EC:
		err = s.SchnorrEC(req, protocolType, stream, curve)
	case pb.SchemaType_CSPAILLIER:
		secKeyPath := filepath.Join(config.LoadTestdataDir(), "cspaillierseckey.txt")
		err = s.CSPaillier(req, secKeyPath, stream)
	case pb.SchemaType_QR:
		group := config.LoadSchnorrGroup()
		err = s.QR(req, group, stream)
	case pb.SchemaType_QNR:
		qr := config.LoadQRRSA("qrsmall") // only for testing
		err = s.QNR(req, qr, stream)
	}

	if err != nil {
		s.logger.Error("Closing RPC due to previous errors")
		return fmt.Errorf("RPC call failed: %v", err)
	}

	s.logger.Notice("RPC finished successfully")
	return nil
}
