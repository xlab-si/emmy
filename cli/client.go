package cli

import (
	"fmt"
	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
	"math/big"
	"strings"
	"sync"
	"time"
)

var ClientCmd = cli.Command{
	Name:        "client",
	Usage:       "A client (prover) that wants to prove something to the server (verifier)",
	Flags:       clientFlags,
	Subcommands: clientSubcommands,
}

// clientSubcommands represent different protocols that can be executed by clients.
var clientSubcommands = []cli.Command{
	{
		Name:     "pedersen",
		Usage:    "Pedersen commitments (modular)",
		Category: "Commitment schemes",
		Flags:    []cli.Flag{protocolVariantFlag, protocolSecretFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				pbVariant, err := parseSchema(ctx.String("variant"))
				if err != nil {
					return err
				}
				dlog := config.LoadDLog("pedersen")
				secret := big.NewInt(ctx.Int64("secret"))
				client, err := client.NewPedersenClient(conn, pbVariant, dlog, secret)
				if err != nil {
					return fmt.Errorf("Error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "pedersen_ec",
		Usage:    "Pedersen commitments (elliptic curves)",
		Category: "Commitment schemes",
		Flags:    []cli.Flag{protocolSecretFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				secret := big.NewInt(ctx.Int64("secret"))
				curve := dlog.P256
				client, err := client.NewPedersenECClient(conn, secret, curve)
				if err != nil {
					return fmt.Errorf("Error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "schnorr",
		Usage:    "Schnorr protocol (modular)",
		Category: "Discrete logatithm proofs",
		Flags:    []cli.Flag{protocolSecretFlag, protocolVariantFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				pbVariant, err := parseSchema(ctx.String("variant"))
				if err != nil {
					return err
				}
				dlog := config.LoadDLog("schnorr")
				secret := big.NewInt(ctx.Int64("secret"))
				client, err := client.NewSchnorrClient(conn, pbVariant, dlog, secret)
				if err != nil {
					return fmt.Errorf("Error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "schnorr_ec",
		Usage:    "Schnorr protocol (elliptic curves)",
		Category: "Discrete logatithm proofs",
		Flags:    []cli.Flag{protocolSecretFlag, protocolVariantFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				dlog := config.LoadDLog("schnorr")
				pbVariant, err := parseSchema(ctx.String("variant"))
				if err != nil {
					return err
				}
				secret := big.NewInt(ctx.Int64("secret"))
				client, err := client.NewSchnorrClient(conn, pbVariant, dlog, secret)
				if err != nil {
					return fmt.Errorf("Error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "cspaillier",
		Usage:    "Camenisch-Shoup verifiable encryption",
		Category: "Encryption",
		Flags:    []cli.Flag{protocolSecretFlag, protocolLabelFlag, protocolPubKeyFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				secret := common.GetRandomInt(big.NewInt(ctx.Int64("secret")))
				label := common.GetRandomInt(big.NewInt(ctx.Int64("label")))
				pubKey := ctx.String("pubkey")
				client, err := client.NewCSPaillierClient(conn, pubKey, secret, label)
				if err != nil {
					return fmt.Errorf("Error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
}

// run accepts pointers to parent (command) and child (subcommand) contexts in order to read
// appropriate command line flags and run a client function either sequentially or concurrently.
// It is supposed to be used as a wrapper around CLI subcommand functions that
// execute client-side of the chosen protocol.
func run(ctx, subCmdCtx *cli.Context, f func(ctx *cli.Context, conn *grpc.ClientConn) error) error {
	var err error
	// conn is a connection to emmy server.
	// In case we are running more than one client, conn will be shared among all the clients.
	// We made it global because it is needed in both 'Before' and 'After' actions of the clientCmd.
	var conn *grpc.ClientConn

	// Establish a connection to emmy server
	client.SetLogLevel(ctx.String("loglevel"))
	conn, err = client.GetConnection(ctx.String("server"), ctx.String("cacert"), ctx.Bool("insecure"))
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Cannot connect to gRPC server: %v", err), 2)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < ctx.Int("n"); i++ {
		fmt.Printf("***Running client #%d***\n", i+1)
		if ctx.Bool("concurrent") {
			wg.Add(1)
			go func() {
				err = f(subCmdCtx, conn)
				defer wg.Done()
			}()
		} else {
			err = f(subCmdCtx, conn)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	// In case the function 'f' returned an error, signal it to the CLI. It means client
	// is in error.
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	fmt.Printf("***Time: %v seconds***\n", elapsed.Seconds())
	return nil
}

// parseSchema parses string equivalents of protocol's variant and returns
// pb.SchemaVariant. If the user requested a variant that doesn't exist, returns an error.
func parseSchema(schemaVariant string) (pb.SchemaVariant, error) {
	variant, success := pb.SchemaVariant_value[strings.ToUpper(schemaVariant)]
	if !success {
		return 0, fmt.Errorf("invalid schema: %s", schemaVariant)
	}
	return pb.SchemaVariant(variant), nil
}
