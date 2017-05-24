package main

import (
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/config"
	_ "golang.org/x/net/trace"
	"google.golang.org/grpc"
	"math"
	"net"
	"net/http"
)

var logger = logging.MustGetLogger("emmy-server")
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

func main() {
	logging.SetFormatter(format)

	/* Listen on the port specified in the config */
	port := config.LoadServerPort()
	connStr := fmt.Sprintf(":%d", port)

	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		logger.Criticalf("Could not connect: %v", err)
	}

	/* Start new GRPC server and register services */
	// Allow as much concurrent streams as possible
	grpc.EnableTracing = true
	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(math.MaxUint32),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)

	// Register our generic service
	logger.Info("Registering services")
	pb.RegisterProtocolServer(grpcServer, NewProtocolServer())

	// Enable debugging
	grpc_prometheus.Register(grpcServer)
	http.Handle("/metrics", prometheus.Handler())
	go http.ListenAndServe(":8881", nil)

	/* From here on, gRPC server will accept connections */
	logger.Infof("GRPC server listening for connections on port %d", port)
	grpcServer.Serve(listener)
}
