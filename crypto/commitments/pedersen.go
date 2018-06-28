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

type PedersenParams struct {
	Group *groups.SchnorrGroup
	H     *big.Int
	a     *big.Int
	// trapdoor a can be nil (doesn't need to be known), it is rarely needed -
	// for example in one of techniques to turn sigma to ZKP
}

func NewPedersenParams(group *groups.SchnorrGroup, H, a *big.Int) *PedersenParams {
	return &PedersenParams{
		Group: group,
		H:     H, // H = group.G^a
		a:     a,
	}
}

func GeneratePedersenParams(bitLengthGroupOrder int) (*PedersenParams, error) {
	group, err := groups.NewSchnorrGroup(bitLengthGroupOrder)
	if err != nil {
		return nil, fmt.Errorf("error when creating SchnorrGroup: %s", err)
	}
	a := common.GetRandomInt(group.Q)
	return NewPedersenParams(group, group.Exp(group.G, a), a), nil
}

type PedersenCommitter struct {
	Params         *PedersenParams
	Commitment     *big.Int
	committedValue *big.Int
	r              *big.Int
}

func NewPedersenCommitter(pedersenParams *PedersenParams) *PedersenCommitter {
	committer := PedersenCommitter{
		Params: pedersenParams,
	}
	return &committer
}

// It receives a value x (to this value a commitment is made), chooses a random x, outputs c = g^x * g^r.
func (c *PedersenCommitter) GetCommitMsg(val *big.Int) (*big.Int, error) {
	if val.Cmp(c.Params.Group.Q) == 1 || val.Cmp(big.NewInt(0)) == -1 {
		err := fmt.Errorf("committed value needs to be in Z_q (order of a base point)")
		return nil, err
	}

	// c = g^x * h^r
	r := common.GetRandomInt(c.Params.Group.Q)

	c.r = r
	c.committedValue = val
	t1 := c.Params.Group.Exp(c.Params.Group.G, val)
	t2 := c.Params.Group.Exp(c.Params.H, r)
	comm := c.Params.Group.Mul(t1, t2)
	c.Commitment = comm

	return comm, nil
}

// It returns values x and r (commitment was c = g^x * g^r).
func (c *PedersenCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	val := c.committedValue
	r := c.r
	return val, r
}

func (c *PedersenCommitter) VerifyTrapdoor(trapdoor *big.Int) bool {
	h := c.Params.Group.Exp(c.Params.Group.G, trapdoor)
	return h.Cmp(c.Params.H) == 0
}

type PedersenReceiver struct {
	Params     *PedersenParams
	commitment *big.Int
}

func NewPedersenReceiver(bitLengthGroupOrder int) (*PedersenReceiver, error) {
	params, err := GeneratePedersenParams(bitLengthGroupOrder)
	if err != nil {
		return nil, err
	}
	return NewPedersenReceiverFromParams(params), nil
}

func NewPedersenReceiverFromParams(params *PedersenParams) *PedersenReceiver {
	return &PedersenReceiver{
		Params: params,
	}
}

func (rcv *PedersenReceiver) GetTrapdoor() *big.Int {
	return rcv.Params.a
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (rcv *PedersenReceiver) SetCommitment(el *big.Int) {
	rcv.commitment = el
}

// When receiver receives a decommitment, CheckDecommitment verifies it against the stored value
// (stored by SetCommitment).
func (rcv *PedersenReceiver) CheckDecommitment(r, val *big.Int) bool {
	t1 := rcv.Params.Group.Exp(rcv.Params.Group.G, val) // g^x
	t2 := rcv.Params.Group.Exp(rcv.Params.H, r)         // h^r
	c := rcv.Params.Group.Mul(t1, t2)                   // g^x * h^r
	return c.Cmp(rcv.commitment) == 0
}
