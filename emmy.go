package main

import (
	"fmt"
	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/server"
	"google.golang.org/grpc"
	"math/big"
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

	// log level applied to client/server loggers
	var logLevel string

	app := cli.NewApp()
	app.Name = "emmy"
	app.Version = "0.1"
	app.Usage = "A CLI app for running emmy server, emmy clients and examples of proofs offered by the emmy library"

	logLevelFlag := cli.StringFlag{
		Name:        "loglevel, l",
		Value:       "info",
		Usage:       "debug|info|notice|error|critical",
		Destination: &logLevel,
	}

	serverApp := cli.Command{
		Name:  "server",
		Usage: "A server that verifies clients (provers)",
		Flags: []cli.Flag{logLevelFlag},
		Subcommands: []cli.Command{
			{
				Name:  "start",
				Usage: "Starts emmy server",
				Action: func(c *cli.Context) error {
					server.SetLogLevel(logLevel)
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
		logLevelFlag,
	}
	clientApp := cli.Command{
		Name:  "client",
		Usage: "A client that wants to prove something to the verifier (server)",
		Flags: clientFlags,
		Action: func(ctx *cli.Context) error {
			client.SetLogLevel(logLevel)
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
			client.SetLogLevel(logLevel)
			server.SetLogLevel(logLevel)
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
// It passes a single gRPC client connection to multiple clients as gRPC is capable of
// multiplexing several RPCs on a single connection
func runClients(n int, concurrently bool, protocolType, protocolVariant, endpoint string) {
	conn, err := client.GetConnection(endpoint)
	if err != nil {
		cLogger.Criticalf("Cannot connect to gRPC server: %v", err)
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		cLogger.Infof("Running client #%d\n", i)
		if concurrently {
			wg.Add(1)
			go func() {
				defer wg.Done()
				runClient(protocolType, protocolVariant, conn)
			}()
		} else {
			runClient(protocolType, protocolVariant, conn)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)
	cLogger.Noticef("Time: %v seconds", elapsed.Seconds())
}

// runClient creates a client for the chosen protocol and executes it.
// Parameters passed to the client in client.ProtocolParams struct have fixed
// values for demonstration purposes.
func runClient(protocolType, protocolVariant string, conn *grpc.ClientConn) {
	_, pbVariant, err := parseSchema(protocolType, protocolVariant)
	if err != nil {
		cLogger.Criticalf("%v", err)
		return
	}

	switch protocolType {
	case "pedersen":
		commitVal := big.NewInt(121212121)
		dlog := config.LoadDLog("pedersen")
		client, err := client.NewPedersenClient(conn, pbVariant, dlog, commitVal)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "pedersen_ec":
		commitVal := big.NewInt(121212121)
		client, err := client.NewPedersenECClient(conn, commitVal)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "schnorr":
		dlog := config.LoadDLog("schnorr")
		secret := big.NewInt(345345345334)
		client, err := client.NewSchnorrClient(conn, pbVariant, dlog, secret)
		if err != nil {
			cLogger.Errorf("Error creating client: %v", err)
		} else {
			err = client.Run()
		}
	case "schnorr_ec":
		secret := big.NewInt(345345345334)
		client, err := client.NewSchnorrECClient(conn, pbVariant, dlog.P256, secret)
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
		client, err := client.NewCSPaillierClient(conn, pubKeyPath, m, label)
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

	// Create and start new instance of emmy server
	server := server.NewProtocolServer()
	server.EnableTracing()
	server.Start(port)
}
