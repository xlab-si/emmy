package benchmark

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/pseudonymsys"
	"github.com/xlab-si/emmy/test"
	"testing"
)

func getMasterNymEC(caClient *client.PseudonymsysCAClientEC) *pseudonymsys.PseudonymEC {
	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")
	dlog := dlog.NewECDLog(dlog.P256)
	nymA := common.NewECGroupElement(dlog.Curve.Params().Gx, dlog.Curve.Params().Gy)
	nymB1, nymB2 := dlog.Exponentiate(nymA.X, nymA.Y, userSecret) // this is user's public key
	nymB := common.NewECGroupElement(nymB1, nymB2)
	masterNym := pseudonymsys.NewPseudonymEC(nymA, nymB)
	return masterNym
}

func getOrgPubKeysEC() *pseudonymsys.OrgPubKeysEC {
	orgName := "org1"
	h1X, h1Y, h2X, h2Y := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	h1 := common.NewECGroupElement(h1X, h1Y)
	h2 := common.NewECGroupElement(h2X, h2Y)
	return pseudonymsys.NewOrgPubKeysEC(h1, h2)
}

func BenchmarkPseudonymsysEC_ObtainCertificate(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClientEC(conn)
	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")
	masterNym := getMasterNymEC(caClient)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		caClient.ObtainCertificate(userSecret, masterNym)
	})
	conn.Close()
}

func BenchmarkPseudonymsysEC_RegisterWithCA(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClientEC(conn)
	c1, _ := client.NewPseudonymsysClientEC(conn)

	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")
	masterNym := getMasterNymEC(caClient)
	caCertificate, _ := caClient.ObtainCertificate(userSecret, masterNym)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		c1.GenerateNym(userSecret, caCertificate)
	})
	conn.Close()
}

func BenchmarkPseudonymsysEC_ObtainCredential(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClientEC(conn)
	c1, _ := client.NewPseudonymsysClientEC(conn)

	masterNym := getMasterNymEC(caClient)
	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")
	caCertificate, _ := caClient.ObtainCertificate(userSecret, masterNym)
	orgPubKeys := getOrgPubKeysEC()
	nym, _ := c1.GenerateNym(userSecret, caCertificate)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		c1.ObtainCredential(userSecret, nym, orgPubKeys)
	})
	conn.Close()
}

func BenchmarkPseudonymsysEC_TransferCredential(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClientEC(conn)
	c1, _ := client.NewPseudonymsysClientEC(conn)
	c2, _ := client.NewPseudonymsysClientEC(conn)

	masterNym := getMasterNymEC(caClient)
	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")
	caCertificate, _ := caClient.ObtainCertificate(userSecret, masterNym)
	nym1, _ := c1.GenerateNym(userSecret, caCertificate)
	orgPubKeys := getOrgPubKeysEC()
	credential, _ := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	nym2, _ := c2.GenerateNym(userSecret, caCertificate)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		c2.TransferCredential("org1", userSecret, nym2, credential)
	})
	conn.Close()
}

func BenchmarkPseudonymsysEC(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	for i, n := range nClients {
		b.Run(benchNames[i], func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.PseudonymsysEC(conn) })
		})
		b.Run(benchNamesConcurr[i], func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.PseudonymsysEC(conn) })
		})
	}
	conn.Close()
}
