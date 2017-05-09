package pseudonymsys

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

type Organization struct {
	DLog *dlog.ZpDLog
	EqualityVerifier *dlogproofs.DLogEqualityVerifier
	a *big.Int
	b *big.Int
	a_tilde *big.Int
	b_tilde *big.Int
}

func NewOrganization() (*Organization) {
	dlog := config.LoadPseudonymsysDLogFromConfig()

	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	verifier, _ := dlogproofs.NewDLogEqualityVerifier()
	org := Organization {
		DLog: dlog,	
		EqualityVerifier: verifier,
	}
	
	return &org
}

func (org *Organization) GetFirstPseudonymsysGenReply(a_tilde, b_tilde *big.Int) *big.Int {
	r := common.GetRandomInt(org.DLog.GetOrderOfSubgroup())
	a, _ := org.DLog.Exponentiate(a_tilde, r)
	b, _ := org.DLog.Exponentiate(b_tilde, r)
	org.a = a
	org.b = b
	org.a_tilde = a_tilde
	org.b_tilde = b_tilde
	return a
}

func (org *Organization) GetPseudonymGenChallenge(x1, x2 *big.Int) *big.Int {
	challenge := org.EqualityVerifier.GetChallenge(org.a_tilde, org.a, 
		org.b_tilde, org.b, x1, x2)
	return challenge
}

func (org *Organization) PseudonymGenVerify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	return verified
}



	
