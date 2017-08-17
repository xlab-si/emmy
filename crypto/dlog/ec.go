package dlog

import (
	"crypto/elliptic"
	"math/big"
)

type Curve int

const (
	P224 Curve = 1 + iota
	P256
	P384
	P521
)

type ECDLog struct {
	Curve           elliptic.Curve
	OrderOfSubgroup *big.Int
}

func NewECDLog(curve Curve) *ECDLog {
	var c elliptic.Curve
	if curve == 1 {
		c = elliptic.P224()
	} else if curve == 2 {
		c = elliptic.P256()
	} else if curve == 3 {
		c = elliptic.P384()
	} else if curve == 4 {
		c = elliptic.P521()
	}

	ecdlog := ECDLog{
		Curve:           c,
		OrderOfSubgroup: c.Params().N, // order of G
	}
	return &ecdlog
}

//func (dlog *ECDLog) Multiply(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
func (dlog *ECDLog) Multiply(params ...*big.Int) (*big.Int, *big.Int) {
	x1 := params[0]
	y1 := params[1]
	x2 := params[2]
	y2 := params[3]

	// calculates (x1, y1) + (x2, y2) as we use elliptic curves
	x, y := dlog.Curve.Add(x1, y1, x2, y2)
	return x, y
}

//func (dlog *ECDLog) Exponentiate(x, y, exponent *big.Int) (*big.Int, *big.Int) {
func (dlog *ECDLog) Exponentiate(params ...*big.Int) (*big.Int, *big.Int) {
	x := params[0]
	y := params[1]
	exponent := params[2]

	// calculates (x, y) * exponent
	hx, hy := dlog.Curve.ScalarMult(x, y, exponent.Bytes())
	return hx, hy
}

func (dlog *ECDLog) ExponentiateBaseG(exponent *big.Int) (*big.Int, *big.Int) {
	// calculates g ^^ exponent or better to say g * exponent as this is elliptic ((gx, gy) * exponent)
	hx, hy := dlog.Curve.ScalarBaseMult(exponent.Bytes())
	return hx, hy
}

func (dlog *ECDLog) GetOrderOfSubgroup() *big.Int {
	return dlog.OrderOfSubgroup
}
