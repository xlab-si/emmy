package main

import (
	"fmt"
	//"github.com/grpc-ecosystem/go-grpc-middleware"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlogproofs"
	"github.com/xlab-si/emmy/encryption"
	"google.golang.org/grpc"
	"log"
	"net"
	"path/filepath"
)

func main() {

	/* Listen on the port specified in the config */
	port := config.LoadServerPort()
	connStr := fmt.Sprintf(":%d", port)

	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		log.Fatalf("Could not connect: %v", err)
	}

	/* Start new GRPC server and register services */
	grpcServer := grpc.NewServer(grpc.MaxConcurrentStreams(1000))
	//grpc.UnaryInterceptor(grpc_middleware.grpc_ctxtags.UnaryServerInterceptor()))
	//grpcServer := grpc.NewServer()

	log.Println("Registering services")
	pb.RegisterPedersenServer(grpcServer, commitments.NewPedersenProtocolServer())
	pb.RegisterPedersenECServer(grpcServer, commitments.NewPedersenECProtocolServer())
	pb.RegisterSchnorrProtocolServer(grpcServer, dlogproofs.NewSchnorrProtocolServer(common.Sigma))
	pb.RegisterSchnorrECProtocolServer(grpcServer, dlogproofs.NewSchnorrECProtocolServer(common.Sigma))

	dir := config.LoadKeyDirFromConfig()
	secKeyPath := filepath.Join(dir, "cspaillierseckey.txt")
	csPaillierProtocolServer, err := encryption.NewCSPaillierProtocolServer(secKeyPath)
	if err != nil {
		log.Printf("Error registering cspaillier: %v", err)
	} else {
		pb.RegisterCSPaillierProtocolServer(grpcServer, csPaillierProtocolServer)
	}

	log.Printf("Starting GRPC server on port %d", port)

	/* From here on, gRPC server will accept connections */
	grpcServer.Serve(listener)
}
