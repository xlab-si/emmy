package main

import (
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xlab-si/emmy/client"
	pb "github.com/xlab-si/emmy/comm/pro"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
	_ "golang.org/x/net/trace"
	"google.golang.org/grpc"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var cLogger = log.ClientLogger
var sLogger = log.ServerLogger

func init() {
	go serve()
}

func main() {

	if len(os.Args) < 2 {
		cLogger.Critical("Usage: go run example.go [pedersen|pedersen_ec|schnorr|schnorr_ec|cspaillier] numClients <concurrent>")
		return
	}

	example := os.Args[1]
	n := 1
	var err error

	if len(os.Args) <= 4 {
		n, err = strconv.Atoi(os.Args[2])
		if err != nil {
			cLogger.Criticalf("Could not convert '%s' to integer, running a single client process\n", os.Args[2])
			n = 1
		}
	}

	runConcurrently := false
	if len(os.Args) == 4 {
		if strings.Compare(os.Args[3], "concurrent") == 0 {
			cLogger.Notice("Will start clients concurrently")
			runConcurrently = true
		} else {
			cLogger.Notice("Will start clients sequentially")
		}
	}

	endpoint := config.LoadServerEndpoint()

	var wg sync.WaitGroup

	start := time.Now()

	for i := 0; i < n; i++ {
		cLogger.Infof("Running client #%d\n", i)
		if runConcurrently {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runExample(endpoint, example, i, n)
			}()
		} else {
			runExample(endpoint, example, i, n)
		}
	}

	wg.Wait()

	elapsed := time.Since(start)
	cLogger.Noticef("Time: %v seconds", elapsed.Seconds())

	return
}

func runExample(endpoint, example string, i, n int) {

	genClient := getGenericClient(endpoint, example)
	if genClient == nil {
		cLogger.Critical("Error ocurred when creating client")
		return
	}

	/* Placeholder for values used to bootstrap chosen protocol
	The actual (example) values will be filled in depending on which protocol we are starting */
	protocolParams := client.ProtocolParams{}

	switch example {
	case "pedersen", "pedersen-zkp", "pedersen-zkpok":
		protocolParams["commitVal"] = *big.NewInt(121212121)
	case "pedersen_ec", "pedersen_ec-zkp", "pedersen_ec-zkpok":
		protocolParams["commitVal"] = *big.NewInt(121212121)
	case "schnorr", "schnorr-zkp", "schnorr-zkpok":
		protocolParams["secret"] = *big.NewInt(345345345334)
	case "schnorr_ec", "schnorr_ec-zkp", "schnorr_ec-zkpok":
		protocolParams["secret"] = *big.NewInt(345345345334)
	case "cspaillier", "cspaillier-zkp", "cspaillier-zkpok":
		protocolParams["m"] = *common.GetRandomInt(big.NewInt(8685849))
		protocolParams["label"] = *common.GetRandomInt(big.NewInt(340002223232))
	default:
		cLogger.Criticalf("ERROR: Invalid example: %s", example)
		return
	}

	genClient.ExecuteProtocol(protocolParams)
}

func getGenericClient(endpoint, schema string) *client.Client {
	schemaTypeVariant := strings.Split(strings.ToUpper(schema), "-")

	// Spawn the client that will execute the protocol of choice
	clientParams := &client.ClientParams{}
	clientParams.SchemaType = schemaTypeVariant[0]
	if len(schemaTypeVariant) > 1 {
		clientParams.SchemaVariant = schemaTypeVariant[1]
	}

	c, err := client.NewProtocolClient(endpoint, clientParams)
	if err != nil {
		cLogger.Critical(err)
		return nil
	}

	return c
}

func serve() {

	/* Listen on the port specified in the config */
	port := config.LoadServerPort()
	connStr := fmt.Sprintf(":%d", port)

	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		sLogger.Criticalf("Could not connect: %v", err)
	}

	/* Start new GRPC server and register services */
	// Allow as much concurrent streams as possible
	grpc.EnableTracing = true
	grpcServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(math.MaxUint32),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)

	// Register our generic service
	sLogger.Info("Registering services")
	pb.RegisterProtocolServer(grpcServer, server.NewProtocolServer())

	// Enable debugging
	grpc_prometheus.Register(grpcServer)
	http.Handle("/metrics", prometheus.Handler())
	go http.ListenAndServe(":8881", nil)

	/* From here on, gRPC server will accept connections */
	sLogger.Infof("GRPC server listening for connections on port %d", port)
	grpcServer.Serve(listener)
}
