/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package types

import (
	"math/big"

	pb "github.com/xlab-si/emmy/protobuf"
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

func CmpECGroupElements(a, b *ECGroupElement) bool {
	if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
		return true
	} else {
		return false
	}
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

type Triple struct {
	A *big.Int
	B *big.Int
	C *big.Int
}

func NewTriple(a, b, c *big.Int) *Triple {
	triple := Triple{A: a, B: b, C: c}
	return &triple
}

type ECTriple struct {
	A *ECGroupElement
	B *ECGroupElement
	C *ECGroupElement
}

func NewECTriple(a, b, c *ECGroupElement) *ECTriple {
	triple := ECTriple{A: a, B: b, C: c}
	return &triple
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

// ServiceInfo holds the data related to the service supported by emmy.
// All fields are exported to ensure access to data from any package.
type ServiceInfo struct {
	Name        string
	Description string
	Provider    string
}

func NewServiceInfo(name, description, provider string) *ServiceInfo {
	return &ServiceInfo{
		Name:        name,
		Description: description,
		Provider:    provider,
	}
}
