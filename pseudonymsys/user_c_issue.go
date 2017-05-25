package pseudonymsys

import (
	"math/big"
	"errors"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/dlogproofs"
)

type OrgPubKeys struct {
	H1 *big.Int
	H2 *big.Int
}

type PseudonymCredential struct {
	SmallAToGamma *big.Int
	SmallBToGamma *big.Int
	AToGamma *big.Int
	BToGamma *big.Int
	T1 []*big.Int
	T2 []*big.Int
}

func IssueCredential(userSecret *big.Int, nym *Pseudonym, 
		orgName string, orgPubKeys *OrgPubKeys, dlog *dlog.ZpDLog) (*PseudonymCredential, error) {
	gamma := common.GetRandomInt(dlog.GetOrderOfSubgroup())
	equalityVerifier1 := dlogproofs.NewDLogEqualityBTranscriptVerifier(dlog, gamma)
	equalityVerifier2 := dlogproofs.NewDLogEqualityBTranscriptVerifier(dlog, gamma)
	org := NewOrgCredentialIssuer(orgName)
	
	// First we need to authenticate - prove that we know dlog_a(b) where (a, b) is a nym registered
	// with this organization. Authentication is done via Schnorr.
	schnorrProver := dlogproofs.NewSchnorrProver(dlog, common.Sigma)
	x := schnorrProver.GetProofRandomData(userSecret, nym.A)
	
	challenge := org.GetAuthenticationChallenge(nym.A, nym.B, x)
	z, _ := schnorrProver.GetProofData(challenge)
	
	x11, x12, x21, x22, A, B, err := org.VerifyAuthentication(z)
	if err != nil {
		return nil, err
	}
	
	// Now the organization needs to prove that it knows log_b(A), log_g(h2) and log_b(A) = log_g(h2).
	// And to prove that it knows log_aA(B), log_g(h1) and log_aA(B) = log_g(h1).
	// g1 = dlog.G, g2 = nym.B, t1 = A, t2 = orgPubKeys.H2

	challenge1 := equalityVerifier1.GetChallenge(dlog.G, nym.B, orgPubKeys.H2, A, x11, x12)
	aA, _ := dlog.Multiply(nym.A, A)
	challenge2 := equalityVerifier2.GetChallenge(dlog.G, aA, orgPubKeys.H1, B, x21, x22)
	
	z1, z2 := org.GetEqualityProofData(challenge1, challenge2)

	verified1, transcript1, bToGamma, AToGamma := equalityVerifier1.Verify(z1)
	verified2, transcript2, aAToGamma, BToGamma := equalityVerifier2.Verify(z2)
	
	aToGamma, _ := dlog.Exponentiate(nym.A, gamma)
	if verified1 && verified2 {
		valid1 := dlogproofs.VerifyBlindedTranscript(transcript1, dlog, dlog.G, orgPubKeys.H2, 
			bToGamma, AToGamma)
		valid2 := dlogproofs.VerifyBlindedTranscript(transcript2, dlog, dlog.G, orgPubKeys.H1, 
			aAToGamma, BToGamma)
		if valid1 && valid2 {
			credential := PseudonymCredential{
				SmallAToGamma: aToGamma,
				SmallBToGamma: bToGamma,
				AToGamma: AToGamma,
				BToGamma: BToGamma,
				T1: transcript1,
				T2: transcript2,
			}
			
			return &credential, nil					
		}
		
	}

	err = errors.New("Organization failed to prove that a credential is valid.")	
	return nil, err
}

	
	
	
		
	