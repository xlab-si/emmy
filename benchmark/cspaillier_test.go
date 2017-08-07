package benchmark

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/test"
	"math/big"
	"testing"
)

func BenchmarkCSPaillier(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	m := common.GetRandomInt(big.NewInt(8685849))
	l := common.GetRandomInt(big.NewInt(340002223232))
	pubkey := "testdata/cspaillierpubkey.txt"

	for i, n := range nClients {
		b.Run(benchNames[i], func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.CSPaillier(conn, m, l, pubkey) })
		})
		b.Run(benchNamesConcurr[i], func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.CSPaillier(conn, m, l, pubkey) })
		})
	}
	conn.Close()
}
