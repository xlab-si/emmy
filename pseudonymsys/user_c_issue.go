package pseudonymsys

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
	"log"
)

type PseudonymCredential struct {

}

func IssueCredential(userSecret *big.Int, nym *Pseudonym, 
		orgName string, dlog *dlog.ZpDLog) (*PseudonymCredential, error) {
	prover := dlogproofs.NewDLogEqualityBTranscriptProver(dlog)
	org := NewOrgCredentialIssuer(orgName)
	
	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is some nym registered
	// by organization. Authentication is done via Schnorr.
	schnorrProver := dlogproofs.NewSchnorrProver(dlog, common.Sigma)
	x, b := schnorrProver.GetProofRandomData(nym.A, userSecret)
	
	challenge := org.GetAuthenticationChallenge(nym.A, b, x)
	z, _ := schnorrProver.GetProofData(challenge)
	
	A, B, err := org.VerifyAuthentication(z)
	if err != nil {
		return nil, err
	}
	

	log.Println(A)
	log.Println(B)

	log.Println(schnorrProver)	
	log.Println(prover)
	log.Println(org)

	//gamma := common.GetRandomInt(dlog.GetOrderOfSubgroup())
	//a_tilde, _ := dlog.ExponentiateBaseG(gamma)
	
	
	return nil, nil
}

	
	
	
	
	
	
	