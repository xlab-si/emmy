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
	pb.PseudonymSystemServer
	pb.PseudonymSystemCAServer
	pb.InfoServer
}

// Server struct implements the EmmyServer interface.
var _ EmmyServer = (*Server)(nil)

type Server struct {
	GrpcServer *grpc.Server
	Logger     log.Logger
	*SessionManager
	*RegistrationManager
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
		GrpcServer: grpc.NewServer(
			grpc.Creds(creds),
			grpc.MaxConcurrentStreams(math.MaxUint32),
			grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		),
		Logger:              logger,
		SessionManager:      sessionManager,
		RegistrationManager: registrationManager,
	}

	// Disable tracing by default, as is used for debugging purposes.
	// The user will be able to turn it on via Server's EnableTracing function.
	grpc.EnableTracing = false

	// Register our services with the supporting gRPC server
	server.registerServices()

	// Initialize gRPC metrics offered by Prometheus package
	grpc_prometheus.Register(server.GrpcServer)

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
	// as grpc server's performance over HTTP (GrpcServer.ServeHTTP) is much worse.
	http.Handle("/metrics", prometheus.Handler())

	// After this, /metrics will be available, along with /debug/requests, /debug/events in
	// case server's EnableTracing function is called.
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	s.Logger.Noticef("Emmy server listening for connections on port %d", port)
	s.GrpcServer.Serve(listener)
	return nil
}

// Teardown stops the protocol server by gracefully stopping enclosed gRPC server.
func (s *Server) Teardown() {
	s.Logger.Notice("Tearing down gRPC server")
	s.GrpcServer.GracefulStop()
}

// EnableTracing instructs the gRPC framework to enable its tracing capability, which
// is mainly used for debugging purposes.
// Although this function does not explicitly affect the Server struct, it is wired to Server
// in order to provide a nicer API when setting up the server.
func (s *Server) EnableTracing() {
	grpc.EnableTracing = true
	s.Logger.Notice("Enabled gRPC tracing")
}

// registerServices binds gRPC server interfaces to the server instance itself, as the server
// provides implementations of these interfaces.
func (s *Server) registerServices() {
	pb.RegisterInfoServer(s.GrpcServer, s)
	pb.RegisterPseudonymSystemServer(s.GrpcServer, s)
	pb.RegisterPseudonymSystemCAServer(s.GrpcServer, s)

	s.Logger.Notice("Registered gRPC Services")
}

func (s *Server) send(msg *pb.Message, stream pb.ServerStream) error {
	if err := stream.Send(msg); err != nil {
		return fmt.Errorf("error sending message: %v", err)
	}
	if msg.ProtocolError != "" {
		s.Logger.Infof("Successfully sent response of type %T", msg.ProtocolError)
	} else {
		s.Logger.Infof("Successfully sent response of type %T", msg.Content)
	}
	s.Logger.Debugf("%+v", msg)

	return nil
}

func (s *Server) receive(stream pb.ServerStream) (*pb.Message, error) {
	resp, err := stream.Recv()
	if err == io.EOF {
		return nil, err
	} else if err != nil {
		return nil, fmt.Errorf("an error occurred: %v", err)
	}
	s.Logger.Infof("Received request of type %T from the stream", resp.Content)
	s.Logger.Debugf("%+v", resp)

	return resp, nil
}
