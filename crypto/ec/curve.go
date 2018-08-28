package ec

import "crypto/elliptic"

type Curve int

const (
	P224 Curve = 1 + iota
	P256
	P384
	P521
)

func GetCurve(c Curve) elliptic.Curve {
	switch c {
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
