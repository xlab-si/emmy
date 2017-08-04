package test

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/pseudonymsys"
	"google.golang.org/grpc"
	"math/big"
)

// In this file we can find function definitions used by packages 'test' and 'benchmark'.
// These functions create and run clients for different schemes.
// Note that all of them accept a pointer to grpc.ClientConn struct, e.g. the client connection
// is created externally, and should be closed externally as well.

func Pedersen(conn *grpc.ClientConn, n *big.Int) error {
	dlog := config.LoadDLog("pedersen")
	c, err := client.NewPedersenClient(conn, pb.SchemaVariant_SIGMA, dlog, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func PedersenEC(conn *grpc.ClientConn, n *big.Int) error {
	c, err := client.NewPedersenECClient(conn, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func Schnorr(conn *grpc.ClientConn, n *big.Int, variant pb.SchemaVariant) error {
	dlog := config.LoadDLog("schnorr")
	c, err := client.NewSchnorrClient(conn, variant, dlog, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func SchnorrEC(conn *grpc.ClientConn, n *big.Int, variant pb.SchemaVariant) error {
	c, err := client.NewSchnorrECClient(conn, variant, dlog.P256, n)
	if err != nil {
		return err
	}
	return c.Run()
}

func CSPaillier(conn *grpc.ClientConn, m, l *big.Int, pubKeyPath string) error {
	c, err := client.NewCSPaillierClient(conn, pubKeyPath, m, l)
	if err != nil {
		return err
	}
	return c.Run()
}

func Pseudonymsys(conn *grpc.ClientConn) (bool, error) {
	var err error

	dlog := config.LoadDLog("pseudonymsys")
	caClient, err := client.NewPseudonymsysCAClient(conn)
	if err != nil {
		return false, err
	}

	userSecret := config.LoadPseudonymsysUserSecret("user1", "dlog")
	p, _ := dlog.Exponentiate(dlog.G, userSecret) // this is user's public key
	masterNym := pseudonymsys.NewPseudonym(dlog.G, p)

	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		return false, err
	}

	// create a client to communicate with org1
	// usually the endpoint is different from the one used for CA:
	c1, err := client.NewPseudonymsysClient(conn)
	// register with org1
	nym1, err := c1.GenerateNym(userSecret, caCertificate)
	if err != nil {
		return false, err
	}

	orgName := "org1"
	h1, h2 := config.LoadPseudonymsysOrgPubKeys(orgName)
	orgPubKeys := pseudonymsys.NewOrgPubKeys(h1, h2)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		return false, err
	}

	// create a client to communicate with org2
	c2, err := client.NewPseudonymsysClient(conn)
	// register with org2
	nym2, err := c2.GenerateNym(userSecret, caCertificate)
	if err != nil {
		return false, err
	}

	authenticated, err := c2.TransferCredential(orgName, userSecret, nym2, credential)
	if err != nil {
		return false, err
	}

	return authenticated, nil
}

func PseudonymsysEC(conn *grpc.ClientConn) (bool, error) {
	var err error

	caClient, err := client.NewPseudonymsysCAClientEC(conn)
	if err != nil {
		return false, err
	}

	userSecret := config.LoadPseudonymsysUserSecret("user1", "ecdlog")
	dlog := dlog.NewECDLog(dlog.P256)
	nymA := common.NewECGroupElement(dlog.Curve.Params().Gx, dlog.Curve.Params().Gy)
	nymB1, nymB2 := dlog.Exponentiate(nymA.X, nymA.Y, userSecret) // this is user's public key
	nymB := common.NewECGroupElement(nymB1, nymB2)
	masterNym := pseudonymsys.NewPseudonymEC(nymA, nymB)

	caCertificate, err := caClient.ObtainCertificate(userSecret, masterNym)
	if err != nil {
		return false, err
	}

	// create a client to communicate with org1
	// usually the endpoint is different from the one used for CA:
	c1, err := client.NewPseudonymsysClientEC(conn)
	// register with org1
	nym1, err := c1.GenerateNym(userSecret, caCertificate)
	if err != nil {
		return false, err
	}

	orgName := "org1"
	h1X, h1Y, h2X, h2Y := config.LoadPseudonymsysOrgPubKeysEC(orgName)
	h1 := common.NewECGroupElement(h1X, h1Y)
	h2 := common.NewECGroupElement(h2X, h2Y)
	orgPubKeys := pseudonymsys.NewOrgPubKeysEC(h1, h2)
	credential, err := c1.ObtainCredential(userSecret, nym1, orgPubKeys)
	if err != nil {
		return false, err
	}

	// create a client to communicate with org2
	c2, err := client.NewPseudonymsysClientEC(conn)
	// register with org2
	nym2, err := c2.GenerateNym(userSecret, caCertificate)
	if err != nil {
		return false, err
	}

	authenticated, err := c2.TransferCredential(orgName, userSecret, nym2, credential)
	if err != nil {
		return false, err
	}
	return authenticated, nil
}
