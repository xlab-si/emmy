package main

import (
	"github.com/urfave/cli"
	emmy "github.com/xlab-si/emmy/cli"
	"os"
)

// main runs the emmy CLI app.
func main() {
	app := cli.NewApp()
	app.Name = "emmy"
	app.Version = "0.1"
	app.Usage = `A CLI app for running emmy server, emmy clients 
		and examples of proofs offered by the emmy library`
	app.Commands = []cli.Command{emmy.ServerCmd, emmy.ClientCmd}

	app.Run(os.Args)
}
