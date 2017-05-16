package pseudonymsys

import (
	"math/big"
	"errors"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
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

	if verified {
		// todo: store in some DB: (orgName, nymA, nymB)
		return &Pseudonym{A: a, B: b}
	} else {
		return nil	
	}
}

func GenerateNymVerifyMaster(userSecret, blindedA, blindedB, r, s *big.Int, 
		orgName, caName string, dlog *dlog.ZpDLog) (*Pseudonym, error) {
	prover := dlogproofs.NewDLogEqualityProver(dlog)
	org := NewOrgNymGenMasterVerifier(orgName)

	gamma := common.GetRandomInt(dlog.GetOrderOfSubgroup())
	nymA, _ := dlog.ExponentiateBaseG(gamma)
	nymB, _ := dlog.Exponentiate(nymA, userSecret)

	// g1 = nymA, g2 = blinded_a
	x1, x2 := prover.GetProofRandomData(userSecret, nymA, blindedA)
	challenge, err := org.GetChallenge(nymA, blindedA, nymB, blindedB, x1, x2, r, s, caName)
	if err != nil {
		return nil, err	
	}

	z := prover.GetProofData(challenge)
	verified := org.Verify(z)

	if verified {
		// todo: store in some DB: (orgName, nymA, nymB)
		return &Pseudonym{A: nymA, B: nymB}, nil
	} else {
		err := errors.New("The proof for nym registration failed.")	
		return nil, err
	}
}




