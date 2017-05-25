package pseudonymsys

import (
	"math/big"
	"errors"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

func TransferCredential(userSecret *big.Int, credential *PseudonymCredential, nym *Pseudonym, 
		orgName string, orgPubKeys *OrgPubKeys, dlog *dlog.ZpDLog) (bool, error) {
	org := NewOrgCredentialVerifier(orgName)
	
	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. But we need also to prove that dlog_a(b) = dlog_a2(b2), where
	// a2, b2 are a1, b1 exponentiated to gamma, and (a1, b1) is a nym for organization that 
	// issued a credential. So we can do both proofs at the same time using DLogEqualityProver.
	equalityProver := dlogproofs.NewDLogEqualityProver(dlog)
	x1, x2 := equalityProver.GetProofRandomData(userSecret, nym.A, credential.SmallAToGamma)
	
	// nym.B = b
	challenge := org.GetAuthenticationChallenge(nym.A, nym.B, 
		credential.SmallAToGamma, credential.SmallBToGamma, x1, x2)
	z := equalityProver.GetProofData(challenge)
	
	verified := org.VerifyAuthentication(z, credential, orgPubKeys)
	if !verified {
		err := errors.New("Authentication with organization failed.")	
		return false, err	
	}
	
	return true, nil	
}

	
	
	
		
	