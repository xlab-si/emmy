package benchmark

import (
	"fmt"
	"github.com/xlab-si/emmy/client"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/test"
	"math/big"
	"testing"
)

func BenchmarkSchnorr(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	val := big.NewInt(345345345334)
	for i, n := range nClients {
		b.Run(fmt.Sprintf("%s-SIGMA", benchNames[i]), func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.Schnorr(conn, val, pb.SchemaVariant_SIGMA) })
		})
		b.Run(fmt.Sprintf("%s-ZKP", benchNames[i]), func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.Schnorr(conn, val, pb.SchemaVariant_ZKP) })
		})

		b.Run(fmt.Sprintf("%s-ZKPOK", benchNames[i]), func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.Schnorr(conn, val, pb.SchemaVariant_ZKPOK) })
		})
		b.Run(fmt.Sprintf("%s-SIGMA", benchNamesConcurr[i]), func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.Schnorr(conn, val, pb.SchemaVariant_SIGMA) })
		})
		b.Run(fmt.Sprintf("%s-ZKP", benchNamesConcurr[i]), func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.Schnorr(conn, val, pb.SchemaVariant_ZKP) })
		})

		b.Run(fmt.Sprintf("%s-ZKPOK", benchNamesConcurr[i]), func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.Schnorr(conn, val, pb.SchemaVariant_ZKPOK) })
		})
	}
	conn.Close()
}
