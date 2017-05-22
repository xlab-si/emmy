package main

import (
	"fmt"
	//"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xlab-si/emmy/base"
	pb "github.com/xlab-si/emmy/comm/pro"
	//"github.com/xlab-si/emmy/commitments"
	//"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	//"github.com/xlab-si/emmy/dlogproofs"
	//"github.com/xlab-si/emmy/encryption"
	"google.golang.org/grpc"
	"log"
	"math"
	"net"
	"net/http"
	//"path/filepath"
	_ "golang.org/x/net/trace"
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
	// Allow as much concurrent streams as possible
	grpc.EnableTracing = true
	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(math.MaxUint32),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)

	log.Println("Registering services")
	// This registers a generic backend service
	pb.RegisterProtocolServer(grpcServer, base.NewProtocolServer())

	grpc_prometheus.Register(grpcServer)
	http.Handle("/metrics", prometheus.Handler())
	go http.ListenAndServe(":8881", nil)

	log.Printf("Starting GRPC server on port %d", port)

	/* From here on, gRPC server will accept connections */
	grpcServer.Serve(listener)
}

// Will be obsolete when generics are ready
/*pb.RegisterPedersenServer(grpcServer, commitments.NewPedersenProtocolServer())
pb.RegisterPedersenECServer(grpcServer, commitments.NewPedersenECProtocolServer())
pb.RegisterPedersenECStreamServer(grpcServer, commitments.NewPedersenECStreamProtocolServer())
pb.RegisterSchnorrProtocolServer(grpcServer, dlogproofs.NewSchnorrProtocolServer(common.Sigma))
pb.RegisterSchnorrECProtocolServer(grpcServer, dlogproofs.NewSchnorrECProtocolServer(common.Sigma))
//pb.RegisterProtocolServer(grpcServer, commitments.NewProtocolServer())

dir := config.LoadKeyDirFromConfig()
secKeyPath := filepath.Join(dir, "cspaillierseckey.txt")
csPaillierProtocolServer, err := encryption.NewCSPaillierProtocolServer(secKeyPath)
if err != nil {
	log.Printf("Error registering cspaillier: %v", err)
} else {
	pb.RegisterCSPaillierProtocolServer(grpcServer, csPaillierProtocolServer)
}*/
