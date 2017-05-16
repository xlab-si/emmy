package pseudonymsys

import (
	"math/big"
	//"errors"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

func RegisterWithCA(caName string, userSecret *big.Int, nym Pseudonym, dlog *dlog.ZpDLog) (*big.Int,
		*big.Int, *big.Int, *big.Int, error) {
	schnorrProver := dlogproofs.NewSchnorrProver(dlog, common.Sigma)
	x := schnorrProver.GetProofRandomData(userSecret, nym.A)

	ca := NewCA(caName)
	challenge := ca.GetChallenge(nym.A, nym.B, x)
	z, _ := schnorrProver.GetProofData(challenge)

	blindedA, blindedB, r, s, err := ca.Verify(z)
	if err == nil {
		return blindedA, blindedB, r, s, nil
	} else {
		return nil, nil, nil, nil, err
	}
}

		
	