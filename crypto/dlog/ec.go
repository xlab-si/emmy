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

func GetEllipticCurve(curveType Curve) elliptic.Curve {
	switch curveType {
	case P224:
		return elliptic.P224()
	case P256:
		return elliptic.P256()
	case P384:
		return elliptic.P384()
	case P521:
		return elliptic.P521()
	}

	return elliptic.P256()
}

func NewECDLog(curveType Curve) *ECDLog {
	c := GetEllipticCurve(curveType)
	ecdlog := ECDLog{
		Curve:           c,
		OrderOfSubgroup: c.Params().N, // order of G
	}
	return &ecdlog
}

func (dlog *ECDLog) Multiply(params ...*big.Int) (*big.Int, *big.Int) {
	x1 := params[0]
	y1 := params[1]
	x2 := params[2]
	y2 := params[3]

	// calculates (x1, y1) + (x2, y2) as we use elliptic curves
	x, y := dlog.Curve.Add(x1, y1, x2, y2)
	return x, y
}

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

func (dlog *ECDLog) Inverse(x, y *big.Int) (*big.Int, *big.Int) {
	orderMin := new(big.Int).Sub(dlog.OrderOfSubgroup, big.NewInt(1))
	invX, invY := dlog.Exponentiate(x, y, orderMin)
	return invX, invY
}

func (dlog *ECDLog) GetOrderOfSubgroup() *big.Int {
	return dlog.OrderOfSubgroup
}
