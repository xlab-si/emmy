package benchmark

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/pseudonymsys"
	"github.com/xlab-si/emmy/test"
	"testing"
)

func getMasterNym(caClient *client.PseudonymsysCAClient) *pseudonymsys.Pseudonym {
	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")
	dlog := config.LoadDLog("pseudonymsys")
	p, _ := dlog.Exponentiate(dlog.G, userSecret) // this is user's public key
	masterNym := pseudonymsys.NewPseudonym(dlog.G, p)
	return masterNym
}

func BenchmarkPseudonymsys_ObtainCertificate(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClient(conn)
	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")
	masterNym := getMasterNym(caClient)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		caClient.ObtainCertificate(userSecret, masterNym)
	})
	conn.Close()
}

func BenchmarkPseudonymsys_RegisterWithCA(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClient(conn)
	c1, _ := client.NewPseudonymsysClient(conn)

	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")
	masterNym := getMasterNym(caClient)
	caCertificate, _ := caClient.ObtainCertificate(userSecret, masterNym)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		c1.GenerateNym(userSecret, caCertificate)
	})
	conn.Close()
}

func BenchmarkPseudonymsys_ObtainCredential(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClient(conn)
	c1, _ := client.NewPseudonymsysClient(conn)

	masterNym := getMasterNym(caClient)
	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")
	caCertificate, _ := caClient.ObtainCertificate(userSecret, masterNym)
	h1, h2 := config.LoadPseudonymsysOrgPubKeys("org1")
	nym, _ := c1.GenerateNym(userSecret, caCertificate)
	orgPubKeys := pseudonymsys.NewOrgPubKeys(h1, h2)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		c1.ObtainCredential(userSecret, nym, orgPubKeys)
	})
	conn.Close()
}

func BenchmarkPseudonymsys_TransferCredential(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	caClient, _ := client.NewPseudonymsysCAClient(conn)
	c1, _ := client.NewPseudonymsysClient(conn)
	c2, _ := client.NewPseudonymsysClient(conn)

	masterNym := getMasterNym(caClient)
	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")
	caCertificate, _ := caClient.ObtainCertificate(userSecret, masterNym)
	h1, h2 := config.LoadPseudonymsysOrgPubKeys("org1")
	nym1, _ := c1.GenerateNym(userSecret, caCertificate)
	orgPubKeys := pseudonymsys.NewOrgPubKeys(h1, h2)
	credential, _ := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	nym2, _ := c2.GenerateNym(userSecret, caCertificate)

	b.ResetTimer()
	benchmarkSequential(b, 1, func() {
		c2.TransferCredential("org1", userSecret, nym2, credential)
	})
	conn.Close()
}

func BenchmarkPseudonymsys(b *testing.B) {
	conn, _ := client.GetConnection(testGrpcServerEndpoint)
	for i, n := range nClients {
		b.Run(benchNames[i], func(b *testing.B) {
			benchmarkSequential(b, n, func() { test.Pseudonymsys(conn) })
		})
		b.Run(benchNamesConcurr[i], func(b *testing.B) {
			benchmarkConcurrent(b, n, func() { test.Pseudonymsys(conn) })
		})
	}
	conn.Close()
}
