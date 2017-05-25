package pseudonymsys

import (
	"math/big"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

type CA struct {
	DLog *dlog.ZpDLog
	SchnorrVerifier *dlogproofs.SchnorrVerifier
	caName string
	a *big.Int
	b *big.Int
	privateKey *ecdsa.PrivateKey
}

func NewCA(caName string) (*CA) {
	dlog := config.LoadPseudonymsysDLog()
	x, y := config.LoadPseudonymsysCAPubKey(caName)
	d := config.LoadPseudonymsysCASecret(caName)

	c := elliptic.P256()
	pubKey := ecdsa.PublicKey{Curve: c, X: x, Y: y}
	privateKey := ecdsa.PrivateKey{PublicKey: pubKey, D: d}

	schnorrVerifier := dlogproofs.NewSchnorrVerifier(dlog, common.Sigma)
	ca := CA {
		DLog: dlog,	
		SchnorrVerifier: schnorrVerifier,
		caName: caName,
		privateKey: &privateKey,
	}
	
	return &ca
}

func (ca *CA) GetChallenge(a, b, x *big.Int) *big.Int {
	// TODO: check if b is really a valuable external user's public master key; if not, close the session

	ca.a = a
	ca.b = b
	ca.SchnorrVerifier.SetProofRandomData(x, a, b)
	challenge, _ := ca.SchnorrVerifier.GetChallenge()
	return challenge
}

func (ca *CA) Verify(z *big.Int) (*big.Int, *big.Int, *big.Int, *big.Int, error) {
	verified := ca.SchnorrVerifier.Verify(z, nil)
	if verified {
		r := common.GetRandomInt(ca.DLog.OrderOfSubgroup)
		blindedA, _ := ca.DLog.Exponentiate(ca.a, r)
		blindedB, _ := ca.DLog.Exponentiate(ca.b, r)
		// blindedA, blindedB must be used only once (never use the same pair for two 
		// different organizations)
			
		hashed := common.HashIntoBytes(blindedA, blindedB)
		r, s, err := ecdsa.Sign(rand.Reader, ca.privateKey, hashed)
		
		if err != nil {
			return nil, nil, nil, nil, err	
		} else {
			return blindedA, blindedB, r, s, nil	
		}
	} else {
	
		err := errors.New("The knowledge of secret was not verified.")	
		return nil, nil, nil, nil, err
	}
}


