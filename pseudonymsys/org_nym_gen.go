package pseudonymsys

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

type OrgNymGen struct {
	DLog *dlog.ZpDLog
	s1 *big.Int
	s2 *big.Int

	// the following fields are needed for nym generation (registration of a user):
	EqualityVerifier *dlogproofs.DLogEqualityVerifier
	a *big.Int
	b *big.Int
	a_tilde *big.Int
	b_tilde *big.Int

	// the following fields are needed for issuing a credential
	SchnorrVerifier *dlogproofs.SchnorrVerifier
}

func NewOrgNymGen(orgName string) (*OrgNymGen) {
	dlog := config.LoadPseudonymsysDLog()

	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	verifier := dlogproofs.NewDLogEqualityVerifier(dlog)
	org := OrgNymGen {
		DLog: dlog,	
		EqualityVerifier: verifier,
	}
	
	return &org
}

func (org *OrgNymGen) GetFirstReply(a_tilde, b_tilde *big.Int) *big.Int {
	r := common.GetRandomInt(org.DLog.GetOrderOfSubgroup())
	a, _ := org.DLog.Exponentiate(a_tilde, r)
	b, _ := org.DLog.Exponentiate(b_tilde, r)
	org.a = a
	org.b = b
	org.a_tilde = a_tilde
	org.b_tilde = b_tilde
	return a
}

func (org *OrgNymGen) GetChallenge(x1, x2 *big.Int) *big.Int {
	challenge := org.EqualityVerifier.GetChallenge(org.a_tilde, org.a, 
		org.b_tilde, org.b, x1, x2)
	return challenge
}

func (org *OrgNymGen) Verify(z *big.Int) bool {
	verified := org.EqualityVerifier.Verify(z)
	if verified {
		// TODO: store (a, b) into a database	
	}
	return verified
}



	
