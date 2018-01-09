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

package commitments

import (
	"errors"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// Committer first needs to know H (it gets it from the receiver).
// Then committer can commit to some value x - it sends to receiver c = g^x * h^r.
// When decommitting, committer sends to receiver r, x; receiver checks whether c = g^x * h^r.
type PedersenECCommitter struct {
	group          *groups.ECGroup
	h              *groups.ECGroupElement
	committedValue *big.Int
	r              *big.Int
}

func NewPedersenECCommitter(curveType groups.ECurve) *PedersenECCommitter {
	group := groups.NewECGroup(curveType)
	committer := PedersenECCommitter{
		group: group,
	}
	return &committer
}

// Value h needs to be obtained from a receiver and then set in a committer.
func (committer *PedersenECCommitter) SetH(h *groups.ECGroupElement) {
	committer.h = h
}

// It receives a value x (to this value a commitment is made), chooses a random x, outputs c = g^x * g^r.
func (committer *PedersenECCommitter) GetCommitMsg(val *big.Int) (*groups.ECGroupElement, error) {
	if val.Cmp(committer.group.Q) == 1 || val.Cmp(big.NewInt(0)) == -1 {
		err := errors.New("the committed value needs to be in Z_q (order of a base point)")
		return nil, err
	}

	// c = g^x * h^r
	r := common.GetRandomInt(committer.group.Q)

	committer.r = r
	committer.committedValue = val
	x1 := committer.group.ExpBaseG(val)
	x2 := committer.group.Exp(committer.h, r)
	c := committer.group.Mul(x1, x2)

	return c, nil
}

// It returns values x and r (commitment was c = g^x * g^r).
func (committer *PedersenECCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	val := committer.committedValue
	r := committer.r

	return val, r
}

func (committer *PedersenECCommitter) VerifyTrapdoor(trapdoor *big.Int) bool {
	h := committer.group.ExpBaseG(trapdoor)
	return h.Equals(committer.h)
}

type PedersenECReceiver struct {
	group      *groups.ECGroup
	a          *big.Int
	h          *groups.ECGroupElement
	commitment *groups.ECGroupElement
}

func NewPedersenECReceiver(curve groups.ECurve) *PedersenECReceiver {
	group := groups.NewECGroup(curve)

	a := common.GetRandomInt(group.Q)
	h := group.ExpBaseG(a)

	receiver := new(PedersenECReceiver)
	receiver.group = group
	receiver.a = a
	receiver.h = h

	return receiver
}

func (s *PedersenECReceiver) GetH() *groups.ECGroupElement {
	return s.h
}

func (s *PedersenECReceiver) GetTrapdoor() *big.Int {
	return s.a
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (s *PedersenECReceiver) SetCommitment(el *groups.ECGroupElement) {
	s.commitment = el
}

// When receiver receives a decommitment, CheckDecommitment verifies it against the stored value
// (stored by SetCommitment).
func (s *PedersenECReceiver) CheckDecommitment(r, val *big.Int) bool {
	a := s.group.ExpBaseG(val) // g^x
	b := s.group.Exp(s.h, r)   // h^r
	c := s.group.Mul(a, b)     // g^x * h^r

	return c.Equals(s.commitment)
}
