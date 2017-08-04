package benchmark

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/test"
	"math/big"
	"testing"
)

func BenchmarkPedersen(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	val := big.NewInt(121212121)

	for i, n := range nClients {
		b.Run(benchNames[i], func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.Pedersen(conn, val) })
		})
		b.Run(benchNamesConcurr[i], func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.Pedersen(conn, val) })
		})
	}
	conn.Close()
}
