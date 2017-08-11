package dlog

import (
	"github.com/xlab-si/emmy/crypto/common"
	"math/big"
)

// TODO: doesn't look like having the same interface for zp_dlog and ecdlog is a good idea; refactor

type ZpDLog struct {
	P               *big.Int // modulus of the group
	G               *big.Int // generator of subgroup
	OrderOfSubgroup *big.Int // order of subgroup
}

func NewZpSchnorr(qBitLength int) (*ZpDLog, error) {
	dlog := ZpDLog{}
	g, q, p, err := common.GetSchnorrGroup(qBitLength)
	dlog.G = g
	dlog.OrderOfSubgroup = q
	dlog.P = p
	return &dlog, err
}

func NewZpSafePrime(modulusBitLength int) (*ZpDLog, error) {
	p, err := common.GetSafePrime(modulusBitLength)
	if err != nil {
		return nil, err
	}
	pMin := new(big.Int)
	pMin.Sub(p, big.NewInt(1))
	q := new(big.Int).Div(pMin, big.NewInt(2))

	g, err := common.GetGeneratorOfZnSubgroup(p, pMin, q)
	if err != nil {
		return nil, err
	}

	zpSafePrime := ZpDLog{
		P:               p,
		G:               g,
		OrderOfSubgroup: q,
	}

	return &zpSafePrime, nil
}

// Multiply multiplies two elements from Z_p. Note that two values are returned
// to make it implementation of DLog interface - the second value is always nil
// (differently as in EC DLog).
//func (dlog *ZpDLog) Multiply(x, y *big.Int) *big.Int {
func (dlog ZpDLog) Multiply(params ...*big.Int) (*big.Int, *big.Int) {
	x := params[0]
	y := params[1]

	r := new(big.Int)
	r.Mul(x, y)
	r.Mod(r, dlog.P)

	// returning two values (second as nil) to make it implement the DLog interface sucks,
	// but other options seem even worse
	return r, nil
}

//func (dlog *ZpDLog) Exponentiate(x, exponent *big.Int) *big.Int {
func (dlog ZpDLog) Exponentiate(params ...*big.Int) (*big.Int, *big.Int) {
	x := params[0]
	exponent := params[1]

	r := new(big.Int)
	r.Exp(x, exponent, dlog.P)
	return r, nil
}

func (dlog ZpDLog) ExponentiateBaseG(exponent *big.Int) (*big.Int, *big.Int) {
	x := new(big.Int)
	x.Exp(dlog.G, exponent, dlog.P)
	return x, nil
}

func (dlog ZpDLog) GetOrderOfSubgroup() *big.Int {
	return dlog.OrderOfSubgroup
}
