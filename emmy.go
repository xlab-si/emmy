package main

import (
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var cLogger = log.ClientLogger
var sLogger = log.ServerLogger

func main() {
	// endpoint where emmy clients will contact emmy server
	emmyServerEndpoint := config.LoadServerEndpoint()

	// whether to run clients concurrently or not
	var runConcurrently bool

	// number of (either concurrent or sequential) clients to run
	var n int

	// protocol type and variant to demonstrate
	var protocolType, protocolVariant string

	app := cli.NewApp()
	app.Name = "emmy"
	app.Version = "0.1"
	app.Usage = "A CLI app for running emmy server, emmy clients and examples of proofs offered by the emmy library"

	serverApp := cli.Command{
		Name:  "server",
		Usage: "A server that verifies clients (provers)",
		Subcommands: []cli.Command{
			{
				Name:  "start",
				Usage: "Starts emmy server",
				Action: func(c *cli.Context) error {
					startEmmyServer()
					return nil
				},
			},
		},
	}

	clientFlags := []cli.Flag{
		cli.StringFlag{
			Name:        "protocol, p",
			Value:       "pedersen",
			Usage:       "pedersen|pedersen_ec|schnorr|schnorr_ec|cspaillier",
			Destination: &protocolType,
		},
		cli.StringFlag{
			Name:        "variant, v",
			Value:       "sigma",
			Usage:       "sigma|zkp|zkpok",
			Destination: &protocolVariant,
		},
		cli.IntFlag{
			Name:        "nclients, n",
			Value:       1,
			Destination: &n,
		},
		cli.BoolFlag{
			Name:        "concurrent",
			Destination: &runConcurrently,
		},
	}
	clientApp := cli.Command{
		Name:  "client",
		Usage: "A client that wants to prove something to the verifier (server)",
		Flags: clientFlags,
		Action: func(ctx *cli.Context) error {
			runClients(n, runConcurrently, protocolType, protocolVariant, emmyServerEndpoint)
			return nil
		},
	}

	exampleApp := cli.Command{
		Name: "example",
		Usage: `An entire example of chosen protocol execution for demonstration.
		Runs both emmy server as well as client(s).`,
		Flags: clientFlags,
		Action: func(ctx *cli.Context) error {
			go startEmmyServer()
			runClients(n, runConcurrently, protocolType, protocolVariant, emmyServerEndpoint)
			return nil
		},
	}

	app.Commands = []cli.Command{serverApp, clientApp, exampleApp}
	app.Run(os.Args)
}

// runClients runs emmy clients for the chosen protocol either concurrently or
// sequentially and times the execution.
func runClients(n int, concurrently bool, protocolType, protocolVariant, endpoint string) {
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		cLogger.Infof("Running client #%d\n", i)
		if concurrently {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runClient(protocolType, protocolVariant, endpoint)
			}()
		} else {
			runClient(protocolType, protocolVariant, endpoint)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)
	cLogger.Noticef("Time: %v seconds", elapsed.Seconds())
}

// runClient creates a client for the chosen protocol and executes it.
// Parameters passed to the client in client.ProtocolParams struct have fixed
// values for demonstration purposes.
func runClient(protocolType, protocolVariant, endpoint string) {
	_, pbVariant, err := parseSchema(protocolType, protocolVariant)
	if err != nil {
		cLogger.Criticalf("%v", err)
		return
	}

	switch protocolType {
	case "pedersen":
		commitVal := big.NewInt(121212121)
		dlog := config.LoadDLog("pedersen")
		client, err := client.NewPedersenClient(endpoint, pbVariant, dlog, commitVal)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "pedersen_ec":
		commitVal := big.NewInt(121212121)
		client, err := client.NewPedersenECClient(endpoint, commitVal)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "schnorr":
		dlog := config.LoadDLog("schnorr")
		secret := big.NewInt(345345345334)
		client, err := client.NewSchnorrClient(endpoint, pbVariant, dlog, secret)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "schnorr_ec":
		ec_dlog := dlog.NewECDLog()
		secret := big.NewInt(345345345334)
		client, err := client.NewSchnorrECClient(endpoint, pbVariant, ec_dlog, secret)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "cspaillier":
		keyDir := config.LoadKeyDirFromConfig()
		pubKeyPath := filepath.Join(keyDir, "cspaillierpubkey.txt")
		m := common.GetRandomInt(big.NewInt(8685849))
		label := common.GetRandomInt(big.NewInt(340002223232))
		client, err := client.NewCSPaillierClient(endpoint, pubKeyPath, m, label)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	default:
		cLogger.Criticalf("ERROR: Invalid protocol type: %s", protocolType)
		return
	}

	if err != nil {
		cLogger.Errorf("FAIL: %v", err)
	} else {
		cLogger.Notice("Protocol successfully finished")
	}
}

// parseSchema parses string equivalents of protocol's type and variant and returns
// appropriate pb.SchemaType and pb.SchemaVariant.
// Returns error case of invalid schemaType or schemaVariant
func parseSchema(schemaType, schemaVariant string) (pb.SchemaType, pb.SchemaVariant, error) {
	schemaType = strings.ToUpper(schemaType)
	schemaVariant = strings.ToUpper(schemaVariant)

	schema, success := pb.SchemaType_value[schemaType]
	if !success {
		return 0, 0, fmt.Errorf("Invalid SchemaType: %v", schemaType)
	}

	variant, success := pb.SchemaVariant_value[schemaVariant]
	if !success {
		return 0, 0, fmt.Errorf("Invalid SchemaVariant: %v", schemaVariant)
	}
	return pb.SchemaType(schema), pb.SchemaVariant(variant), nil
}

// startEmmyServer configures and starts the gRPC server.
func startEmmyServer() {
	// Listen on the port specified in the config
	port := config.LoadServerPort()
	connStr := fmt.Sprintf(":%d", port)

	listener, err := net.Listen("tcp", connStr)
	if err != nil {
		sLogger.Criticalf("Could not connect: %v", err)
	}

	// Start new gRPC server and register services, while allowing
	// as much concurrent streams as possible
	grpc.EnableTracing = true
	emmyServer := grpc.NewServer(
		grpc.MaxConcurrentStreams(math.MaxUint32),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
	)

	// Register our generic service
	sLogger.Info("Registering services")
	pb.RegisterProtocolServer(emmyServer, server.NewProtocolServer())

	// Enable debugging
	grpc_prometheus.Register(emmyServer)
	http.Handle("/metrics", prometheus.Handler())
	go http.ListenAndServe(":8881", nil)

	// From here on, gRPC server will accept connections
	sLogger.Infof("Emmy server listening for connections on port %d", port)
	emmyServer.Serve(listener)
}
