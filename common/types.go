package common

import (
	pb "github.com/xlab-si/emmy/comm/pro"
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

func ToECGroupElement(el *pb.ECGroupElement) *ECGroupElement {
	x := ECGroupElement{X: new(big.Int).SetBytes(el.X), Y: new(big.Int).SetBytes(el.Y)}
	return &x
}

func ToPbECGroupElement(el *ECGroupElement) *pb.ECGroupElement {
	x := pb.ECGroupElement{X: el.X.Bytes(), Y: el.Y.Bytes()}
	return &x
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
