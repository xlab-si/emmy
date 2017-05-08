package dlogproofs

import (
	"math/big"
	"github.com/xlab-si/emmy/common"
	"github.com/xlab-si/emmy/dlog"
)


// not finished

type DLogEqualityBTranscriptProver struct {
	DLog *dlog.ZpDLog
	r *big.Int
	secret *big.Int
	g1 *big.Int
	g2 *big.Int
}

func NewDLogEqualityBTranscriptProver() (*DLogEqualityBTranscriptProver, error) {
	p, _ := new(big.Int).SetString("16714772973240639959372252262788596420406994288943442724185217359247384753656472309049760952976644136858333233015922583099687128195321947212684779063190875332970679291085543110146729439665070418750765330192961290161474133279960593149307037455272278582955789954847238104228800942225108143276152223829168166008095539967222363070565697796008563529948374781419181195126018918350805639881625937503224895840081959848677868603567824611344898153185576740445411565094067875133968946677861528581074542082733743513314354002186235230287355796577107626422168586230066573268163712626444511811717579062108697723640288393001520781671", 10)
	g, _ := new(big.Int).SetString("13435884250597730820988673213378477726569723275417649800394889054421903151074346851880546685189913185057745735207225301201852559405644051816872014272331570072588339952516472247887067226166870605704408444976351128304008060633104261817510492686675023829741899954314711345836179919335915048014505501663400445038922206852759960184725596503593479528001139942112019453197903890937374833630960726290426188275709258277826157649744326468681842975049888851018287222105796254410594654201885455104992968766625052811929321868035475972753772676518635683328238658266898993508045858598874318887564488464648635977972724303652243855656", 10)
	q, _ := new(big.Int).SetString("98208916160055856584884864196345443685461747768186057136819930381973920107591", 10)
	dlog := dlog.ZpDLog{
		P: p,
		G: g,
		OrderOfSubgroup: q,
	}
	prover := DLogEqualityBTranscriptProver {
		DLog: &dlog,
	}
	
    return &prover, nil
}

// Sets the values that are needed before the protocol can be run.
// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and 
// that log_g1(t1) = log_g2(t2).
func (prover *DLogEqualityBTranscriptProver) SetInputData(g1, g2 *big.Int) {
	prover.g1 = g1
	prover.g2 = g2
}

// Prove that you know dlog_g1(h1), dlog_g2(h2) and that dlog_g1(h1) = dlog_g2(h2).
func (prover *DLogEqualityBTranscriptProver) GetProofRandomData(secret *big.Int) (*big.Int, *big.Int) {
	prover.secret = secret
	r := common.GetRandomInt(prover.DLog.GetOrderOfSubgroup())
	prover.r = r
    x1, _ := prover.DLog.Exponentiate(prover.g1, r)	
    x2, _ := prover.DLog.Exponentiate(prover.g2, r)	
	return x1, x2
}

func (prover *DLogEqualityBTranscriptProver) GetProofData(challenge *big.Int) (*big.Int) {
	// z = r + challenge * secret
	z := new(big.Int)
	z.Mul(challenge, prover.secret)
	z.Add(z, prover.r)
	z.Mod(z, prover.DLog.GetOrderOfSubgroup())
	return z
}


type DLogEqualityBTranscriptVerifier struct {
	DLog *dlog.ZpDLog
	gamma *big.Int
	challenge *big.Int
	g1 *big.Int
	g2 *big.Int
	x1 *big.Int
	x2 *big.Int
	t1 *big.Int
	t2 *big.Int
}

func NewDLogEqualityBTranscriptVerifier() (*DLogEqualityBTranscriptVerifier, error) {
	p, _ := new(big.Int).SetString("16714772973240639959372252262788596420406994288943442724185217359247384753656472309049760952976644136858333233015922583099687128195321947212684779063190875332970679291085543110146729439665070418750765330192961290161474133279960593149307037455272278582955789954847238104228800942225108143276152223829168166008095539967222363070565697796008563529948374781419181195126018918350805639881625937503224895840081959848677868603567824611344898153185576740445411565094067875133968946677861528581074542082733743513314354002186235230287355796577107626422168586230066573268163712626444511811717579062108697723640288393001520781671", 10)
	g, _ := new(big.Int).SetString("13435884250597730820988673213378477726569723275417649800394889054421903151074346851880546685189913185057745735207225301201852559405644051816872014272331570072588339952516472247887067226166870605704408444976351128304008060633104261817510492686675023829741899954314711345836179919335915048014505501663400445038922206852759960184725596503593479528001139942112019453197903890937374833630960726290426188275709258277826157649744326468681842975049888851018287222105796254410594654201885455104992968766625052811929321868035475972753772676518635683328238658266898993508045858598874318887564488464648635977972724303652243855656", 10)
	q, _ := new(big.Int).SetString("98208916160055856584884864196345443685461747768186057136819930381973920107591", 10)

	dlog := dlog.ZpDLog{
		P: p,
		G: g,
		OrderOfSubgroup: q,
	}
	gamma := common.GetRandomInt(dlog.GetOrderOfSubgroup())
	verifier := DLogEqualityBTranscriptVerifier {
		DLog: &dlog,
		gamma: gamma,
	}
	
    return &verifier, nil
}

// Sets the values that are needed before the protocol can be run.
// The protocol proves the knowledge of log_g1(t1), log_g2(t2) and 
// that log_g1(t1) = log_g2(t2).
func (verifier *DLogEqualityBTranscriptVerifier) SetInputData(g1, g2, t1, t2 *big.Int) {
	verifier.g1 = g1
	verifier.g2 = g2
	verifier.t1 = t1
	verifier.t2 = t2
}

// Sets the values g1^r1 and g2^r2.
func (verifier *DLogEqualityBTranscriptVerifier) SetProofRandomData(x1, x2 *big.Int) {
	verifier.x1 = x1
	verifier.x2 = x2
}

func (verifier *DLogEqualityBTranscriptVerifier) GenerateChallenge() (*big.Int) {
	/*
	alpha := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
	beta := common.GetRandomInt(verifier.DLog.GetOrderOfSubgroup())
	
	// alpha1 = g1^r * g1^alpha * t1^beta
	// beta1 = (g2^r * g2^alpha * t2^beta)^gamma
	alpha1, _ := verifier.DLog.Exponentiate(verifier.g1, alpha)
	alpha1, _ = verifier.DLog.Multiply(verifier.x1, alpha1)
	tmp, _ := verifier.DLog.Exponentiate(verifier.t1, beta)
	alpha1, _ = verifier.DLog.Multiply(alpha1, tmp)
	
	beta1, _ := verifier.DLog.Exponentiate(verifier.g2, alpha)
	beta1, _ = verifier.DLog.Multiply(verifier.x2, beta1)
	tmp, _ = verifier.DLog.Exponentiate(verifier.t2, beta)
	beta1, _ = verifier.DLog.Multiply(beta1, tmp)
	beta1, _ = verifier.DLog.Exponentiate(beta1, verifier.gamma)
	*/
	
	challenge := big.NewInt(3424) // testing
    verifier.challenge = challenge
    return challenge
}

// It receives z = r + secret * challenge. 
//It returns true if g1^z = g1^r * (g1^secret) ^ challenge and g2^z = g2^r * (g2^secret) ^ challenge.
func (verifier *DLogEqualityBTranscriptVerifier) Verify(z *big.Int) (bool) {
	left1, _ := verifier.DLog.Exponentiate(verifier.g1, z)	
	left2, _ := verifier.DLog.Exponentiate(verifier.g2, z)	

    r11, _ := verifier.DLog.Exponentiate(verifier.t1, verifier.challenge)	
    r12, _ := verifier.DLog.Exponentiate(verifier.t2, verifier.challenge)	
    right1, _ := verifier.DLog.Multiply(r11, verifier.x1)	
    right2, _ := verifier.DLog.Multiply(r12, verifier.x2)	
	
	if left1.Cmp(right1) == 0 && left2.Cmp(right2) == 0 {
		return true
	} else {
		return false
	}
	
	
	// g^(z+alpha) = alpha1 * t1^(c-beta)
	// G2^(z+alpha) = beta1 * T2^(c-beta)
	// transcript ((alpha1, beta1), hash(alpha1, beta1), z+alpha)
}





