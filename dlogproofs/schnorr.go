package dlogproofs

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/commitments"
	"github.com/xlab-si/emmy/dlog"
)

// Proving that it knows w such that g^w = h (mod p).
type SchnorrProver struct {
	DLog *dlog.ZpDLog
	secret *big.Int
	r *big.Int
	pedersenReceiver *commitments.PedersenReceiver // only needed for ZKP and ZKPOK, not for sigma
	protocolType common.ProtocolType
}

func NewSchnorrProver(protocolType common.ProtocolType) (*SchnorrProver, error) {
	var prover SchnorrProver
	dLog, err := dlog.NewZpSchnorr(256)
	if err != nil {
		return nil, err 
	}
	
	prover = SchnorrProver {
		DLog: dLog,
		protocolType: protocolType,
	}
	
	if protocolType != common.Sigma {
		// TODO: currently Pedersen is using the same dlog as SchnorrProver, this
		// is because SchnorrVerifier for ZKP/ZKPOK needs to know Pedersen's dlog 
		// to generate a challenge and create a commitment
		prover.pedersenReceiver = commitments.NewPedersenReceiverFromExistingDLog(dLog)
	}
	
    return &prover, nil
}

// Returns pedersenReceiver's h. Verifier needs h to prepare a commitment.
func (prover *SchnorrProver) GetOpeningMsg() (*big.Int, *big.Int, *big.Int, *big.Int) {
	h := prover.pedersenReceiver.GetH()
	group := prover.pedersenReceiver.GetGroup()
	return h, group.P, group.OrderOfSubgroup, group.G
}

// It contains also value t = g^secret. TODO: t (public key) might be transferred at a different stage.
func (prover *SchnorrProver) GetProofRandomData(secret *big.Int) (*big.Int, *big.Int) {
	// x = g^r % p, where r is random
	prover.secret = secret
	r := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	prover.r = r
    x, _ := prover.DLog.ExponentiateBaseG(r)	
    t, _ := prover.DLog.ExponentiateBaseG(secret) // t can be considered as a public key
    
    return x, t
}

// It receives challenge defined by a verifier, and returns z = r + challenge * w
// and trapdoor in ZKPOK.
func (prover *SchnorrProver) GetProofData(challenge *big.Int) (*big.Int, *big.Int) {
	// z = r + challenge * w
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

type SchnorrVerifier struct {
	DLog *dlog.ZpDLog
	x *big.Int
	t *big.Int
	challenge *big.Int
	pedersenCommitter *commitments.PedersenCommitter // not needed in sigma protocol, only in ZKP and ZKPOK
	protocolType common.ProtocolType
}

func NewSchnorrVerifier(protocolType common.ProtocolType) *SchnorrVerifier {
	verifier := SchnorrVerifier {
		protocolType: protocolType,
	}
	if protocolType != common.Sigma {
		verifier.pedersenCommitter = commitments.NewPedersenCommitter()
	}
    return &verifier
}

// GenerateChallenge is used in ZKP where challenge needs to be 
// chosen (and committed to) before sigma protocol starts.
func (verifier *SchnorrVerifier) GenerateChallenge() (*big.Int) {
	challenge := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
    verifier.challenge = challenge
    return challenge
}

func (verifier *SchnorrVerifier) SetCommitmentGroup(p, q, g *big.Int) {
	verifier.pedersenCommitter.SetGroup(p, q, g)
}

func (verifier *SchnorrVerifier) GetOpeningMsgReply(h *big.Int) (*big.Int) {
	verifier.pedersenCommitter.SetH(h) // h = g^a where a is a trapdoor
	challenge := verifier.GenerateChallenge()
	commitment, _ := verifier.pedersenCommitter.GetCommitMsg(challenge)
	return commitment
}

func (verifier *SchnorrVerifier) SetProofRandomData(x *big.Int, t *big.Int) {
	verifier.x = x
	verifier.t = t
}

func (verifier *SchnorrVerifier) SetGroup(p, q, g *big.Int) {
	dlog := dlog.ZpDLog {
		P: p,
		OrderOfSubgroup: q,
		G: g,
	}
    verifier.DLog = &dlog
}

// It returns a challenge and commitment to challenge (this latter only for ZKP and ZKPOK).
func (verifier *SchnorrVerifier) GetChallenge() (*big.Int, *big.Int) {
    if verifier.protocolType == common.Sigma {
    	challenge := verifier.GenerateChallenge()
    	return challenge, nil
	} else {
		challenge, r2 := verifier.pedersenCommitter.GetDecommitMsg()
    	return challenge, r2
	}
}

// It receives y = r + w * challenge. It returns true if g^y = g^r * (g^w) ^ challenge, otherwise false.
func (verifier *SchnorrVerifier) Verify(z *big.Int, trapdoor *big.Int) (bool) {
	if verifier.protocolType == common.ZKPOK {
		valid := verifier.pedersenCommitter.VerifyTrapdoor(trapdoor)
		if !valid {
			return false
		}
	}
    
    left, _ := verifier.DLog.ExponentiateBaseG(z)	
    r1, _ := verifier.DLog.Exponentiate(verifier.t, verifier.challenge)	
    right, _ := verifier.DLog.Multiply(r1, verifier.x)	
	
	if left.Cmp(right) == 0 {
		return true
	} else {
		return false
	}
}


