package dlogproofs

import (
	"math/big"
	"github.com/xlab-si/emmy/dlog"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/commitments"
)

// Note that this is zero knowledge proof (contructed from sigma protocol) -
// this is protocol 6.5.1 from Hazay-Lindell.
// 
// It can be turned into zero knowledge proof of knowledge (6.5.4 from Hazay-Lindell) if
// proofOfKnowledge is set to true in third message. 
//
// First the prover sends h (h = g^a where a is trapdoor) to the verifier.
// Verifier chooses challenge e and commit to it (sends back c = g^e * h^r1 where r1 is random).
// Prover sends the first message of sigma protocol (g^r2 where r2 is random).
// Verifier decommit to e (sends e and r1).
// Prover sends z = r2 + secret * e.
//
// h -->
// <-- c = g^e * h^r1
// g^r2 -- >
// <-- e, r1
// z = r2 + secret * e -->  (if ZKPOK, trapdoor is sent as well)
type SchnorrECProver struct {
	DLog *dlog.ECDLog
	secret *big.Int
	r *big.Int // ProofRandomData
	pedersenReceiver *commitments.PedersenECReceiver // only needed for ZKP and ZKPOK, not for sigma
	protocolType common.ProtocolType
}

func NewSchnorrECProver(protocolType common.ProtocolType) (*SchnorrECProver, error) {
	dLog := dlog.NewECDLog()
	prover := SchnorrECProver {
		DLog: dLog,
		protocolType: protocolType,
	}	
	
	if protocolType != common.Sigma {
		prover.pedersenReceiver = commitments.NewPedersenECReceiver()
	}
	
    return &prover, nil
}

// Returns pedersenReceiver's h. Verifier needs h to prepare a commitment.
func (prover *SchnorrECProver) GetOpeningMsg() *common.ECGroupElement {
	return prover.pedersenReceiver.GetH()
}

// It contains also value t = g^secret. TODO: t (public key) might be transferred at a different stage.
func (prover *SchnorrECProver) GetProofRandomData(secret *big.Int) (*common.ECGroupElement, 
		*common.ECGroupElement) {
	r := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	prover.r = r
	prover.secret = secret
    x1, x2 := prover.DLog.ExponentiateBaseG(r)	
    
    t1, t2 := prover.DLog.ExponentiateBaseG(secret) // t can be considered as a public key
    
    return &common.ECGroupElement{X: x1, Y: x2}, &common.ECGroupElement{X: t1, Y: t2}
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w
// and trapdoor in ZKPOK.
func (prover *SchnorrECProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int) {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())
	
	if prover.protocolType != common.ZKPOK {
		return z, nil
	} else {
		trapdoor := prover.pedersenReceiver.GetTrapdoor()
		return z, trapdoor
	}
}

type SchnorrECVerifier struct {
	DLog *dlog.ECDLog
	x *common.ECGroupElement
	t *common.ECGroupElement
	challenge *big.Int	
	pedersenCommitter *commitments.PedersenECCommitter // not needed in sigma protocol, only in ZKP and ZKPOK
	protocolType common.ProtocolType
}

func NewSchnorrECVerifier(protocolType common.ProtocolType) *SchnorrECVerifier {
	dLog := dlog.NewECDLog()
	verifier := SchnorrECVerifier {
		DLog: dLog,
		protocolType: protocolType,
	}
	
	if protocolType != common.Sigma {
		verifier.pedersenCommitter = commitments.NewPedersenECCommitter()
	}
	
    return &verifier
}

// GenerateChallenge is used in ZKP where challenge needs to be 
// chosen (and committed to) before sigma protocol starts.
func (verifier *SchnorrECVerifier) GenerateChallenge() (*big.Int) {
	challenge := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
    verifier.challenge = challenge
    return challenge
}

func (verifier *SchnorrECVerifier) GetOpeningMsgReply(h *common.ECGroupElement) (*common.ECGroupElement) {
	verifier.pedersenCommitter.SetH(h) // h = g^a where a is a trapdoor
	challenge := verifier.GenerateChallenge()
	commitment, _ := verifier.pedersenCommitter.GetCommitMsg(challenge)
	return commitment
}

// TODO: t transferred at some other stage?
func (verifier *SchnorrECVerifier) SetProofRandomData(x *common.ECGroupElement, t *common.ECGroupElement) {
    verifier.x = x
    verifier.t = t
}

// It returns a challenge and commitment to challenge (this latter only for ZKP and ZKPOK).
func (verifier *SchnorrECVerifier) GetChallenge() (*big.Int, *big.Int) {    
	if verifier.protocolType == common.Sigma {
    	challenge := verifier.GenerateChallenge()
    	return challenge, nil
	} else {
		challenge, r2 := verifier.pedersenCommitter.GetDecommitMsg()
    	return challenge, r2
	}
}

func (verifier *SchnorrECVerifier) Verify(z *big.Int, trapdoor *big.Int) (bool) {
	if verifier.protocolType == common.ZKPOK {
		valid := verifier.pedersenCommitter.VerifyTrapdoor(trapdoor)
		if !valid {
			return false
		}
	}
	left1, left2 := verifier.DLog.ExponentiateBaseG(z)	
	
    r1, r2 := verifier.DLog.Exponentiate(verifier.t.X, verifier.t.Y, verifier.challenge)	
    right1, right2 := verifier.DLog.Multiply(r1, r2, verifier.x.X, verifier.x.Y)	
	
	if (left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0) {
		return true
	} else {
		return false
	}
}


