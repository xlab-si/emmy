package types

import (
	pb "github.com/xlab-si/emmy/protobuf"
	"math/big"
)

type ProtocolType uint8

const (
	Sigma ProtocolType = iota + 1 // SigmaProtocol
	ZKP                           //ZeroKnowledgeProof
	ZKPOK                         //ZeroKnowledgeProofOfKnowledge
)

type ECGroupElement struct {
	X *big.Int
	Y *big.Int
}

func NewECGroupElement(x, y *big.Int) *ECGroupElement {
	return &ECGroupElement{X: x, Y: y}
}

func ToECGroupElement(el *pb.ECGroupElement) *ECGroupElement {
	x := ECGroupElement{X: new(big.Int).SetBytes(el.X), Y: new(big.Int).SetBytes(el.Y)}
	return &x
}

func ToPbECGroupElement(el *ECGroupElement) *pb.ECGroupElement {
	x := pb.ECGroupElement{X: el.X.Bytes(), Y: el.Y.Bytes()}
	return &x
}

// Pair is the same as ECGroupElement, but to be used in non EC schemes when a pair of
// *big.Int is needed.
type Pair struct {
	A *big.Int
	B *big.Int
}

func ToPair(el *pb.Pair) *Pair {
	x := Pair{A: new(big.Int).SetBytes(el.A), B: new(big.Int).SetBytes(el.B)}
	return &x
}

func ToPbPair(el *Pair) *pb.Pair {
	x := pb.Pair{A: el.A.Bytes(), B: el.B.Bytes()}
	return &x
}

func NewPair(a, b *big.Int) *Pair {
	pair := Pair{A: a, B: b}
	return &pair
}

func ToProtocolType(variant pb.SchemaVariant) ProtocolType {
	switch variant {
	case pb.SchemaVariant_ZKP:
		return ZKP
	case pb.SchemaVariant_ZKPOK:
		return ZKPOK
	default:
		return Sigma
	}
}
