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
	"math/big"

	"fmt"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

// TODO: might be better to have only one method (like GetCommitment) instead of
// GetCommitMsg and GetDecommit msg, which would return c, r. Having two methods and storing r into
// committer might be awkward when having more commitments (like in RSABasedCommitment when
// proving multiplication property, see commitments_test.go).

// Committer first needs to know H (it gets it from the receiver).
// Then committer can commit to some value x - it sends to receiver c = g^x * h^r.
// When decommitting, committer sends to receiver r, x; receiver checks whether c = g^x * h^r.
type PedersenCommitter struct {
	Group          *groups.SchnorrGroup
	H              *big.Int
	committedValue *big.Int
	r              *big.Int
}

func NewPedersenCommitter(group *groups.SchnorrGroup) *PedersenCommitter {
	committer := PedersenCommitter{
		Group: group,
	}
	return &committer
}

// Value h needs to be obtained from a receiver and then set in a committer.
func (committer *PedersenCommitter) SetH(h *big.Int) {
	committer.H = h
}

// It receives a value x (to this value a commitment is made), chooses a random x, outputs c = g^x * g^r.
func (committer *PedersenCommitter) GetCommitMsg(val *big.Int) (*big.Int, error) {
	if val.Cmp(committer.Group.Q) == 1 || val.Cmp(big.NewInt(0)) == -1 {
		err := fmt.Errorf("committed value needs to be in Z_q (order of a base point)")
		return nil, err
	}

	// c = g^x * h^r
	r := common.GetRandomInt(committer.Group.Q)

	committer.r = r
	committer.committedValue = val
	t1 := committer.Group.Exp(committer.Group.G, val)
	t2 := committer.Group.Exp(committer.H, r)
	c := committer.Group.Mul(t1, t2)

	return c, nil
}

// It returns values x and r (commitment was c = g^x * g^r).
func (committer *PedersenCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	val := committer.committedValue
	r := committer.r
	return val, r
}

func (committer *PedersenCommitter) VerifyTrapdoor(trapdoor *big.Int) bool {
	h := committer.Group.Exp(committer.Group.G, trapdoor)
	return h.Cmp(committer.H) == 0
}

type PedersenReceiver struct {
	Group      *groups.SchnorrGroup
	H          *big.Int
	a          *big.Int
	commitment *big.Int
}

func NewPedersenReceiver(bitLengthGroupOrder int) (*PedersenReceiver, error) {
	group, err := groups.NewSchnorrGroup(bitLengthGroupOrder)
	if err != nil {
		return nil, fmt.Errorf("error when creating SchnorrGroup: %s", err)
	}
	return NewPedersenReceiverFromExistingSchnorr(group), nil
}

func NewPedersenReceiverFromExistingSchnorr(group *groups.SchnorrGroup) *PedersenReceiver {
	a := common.GetRandomInt(group.Q)
	return &PedersenReceiver{
		Group: group,
		H:     group.Exp(group.G, a),
		a:     a,
	}
}

func (s *PedersenReceiver) GetTrapdoor() *big.Int {
	return s.a
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (s *PedersenReceiver) SetCommitment(el *big.Int) {
	s.commitment = el
}

// When receiver receives a decommitment, CheckDecommitment verifies it against the stored value
// (stored by SetCommitment).
func (s *PedersenReceiver) CheckDecommitment(r, val *big.Int) bool {
	t1 := s.Group.Exp(s.Group.G, val) // g^x
	t2 := s.Group.Exp(s.H, r)         // h^r
	c := s.Group.Mul(t1, t2)          // g^x * h^r
	return c.Cmp(s.commitment) == 0
}
