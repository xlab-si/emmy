package pseudonymsys

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"log"
)

type Pseudonym struct {
	A *big.Int
	B *big.Int
}

func GenerateNym(userSecret *big.Int, orgName string, dlog *dlog.ZpDLog) *Pseudonym {
	prover := dlogproofs.NewDLogEqualityProver(dlog)
	// g1 = a_tilde, t1 = b_tilde,
	// g2 = a, t2 = b
	org := NewOrgNymGen(orgName)

	gamma := common.GetRandomInt(dlog.GetOrderOfSubgroup())
	a_tilde, _ := dlog.ExponentiateBaseG(gamma)
	b_tilde, _ := dlog.Exponentiate(a_tilde, userSecret)

	a := org.GetFirstReply(a_tilde, b_tilde)

	b, _ := dlog.Exponentiate(a, userSecret)
	x1, x2 := prover.GetProofRandomData(userSecret, a_tilde, a)

	challenge := org.GetChallenge(x1, x2)

	z := prover.GetProofData(challenge)
	verified := org.Verify(z)

	log.Println(verified)
	if verified {
		// todo: store in some DB: (orgName, nymA, nymB)
		return &Pseudonym{A: a, B: b}
	} else {
		return nil	
	}
}




