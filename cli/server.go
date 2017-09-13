package cli

import (
	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/server"
)

var ServerCmd = cli.Command{
	Name:  "server",
	Usage: "A server (verifier) that verifies clients (provers)",
	Subcommands: []cli.Command{
		{
			Name:  "start",
			Usage: "Starts emmy server",
			Flags: serverFlags,
			Action: func(ctx *cli.Context) error {
				server.SetLogLevel(ctx.String("loglevel"))
				err := startEmmyServer(ctx.Int("port"), ctx.String("cert"), ctx.String("key"))
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				return nil
			},
		},
	},
}

// startEmmyServer configures and starts the gRPC server at the desired port
func startEmmyServer(port int, certPath, keyPath string) error {
	srv, err := server.NewProtocolServer(certPath, keyPath)
	if err != nil {
		return err
	}
	srv.EnableTracing()
	return srv.Start(port)
}
