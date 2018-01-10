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
	"fmt"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

type DamgardFujisakiCommitter struct {
	QRSpecialRSA   *groups.QRSpecialRSA
	H              *big.Int
	G              *big.Int // G = H^alpha % N
	committedValue *big.Int
	r              *big.Int
}

func NewDamgardFujisakiCommitter(n, h, g *big.Int) *DamgardFujisakiCommitter {
	return &DamgardFujisakiCommitter{
		QRSpecialRSA: groups.NewQRSpecialRSAPublic(n),
		H:            h,
		G:            g,
	}
}

func (committer *DamgardFujisakiCommitter) GetCommitMsg(a *big.Int) (*big.Int, error) {
	group := committer.QRSpecialRSA
	if a.Cmp(group.N) != -1 {
		err := fmt.Errorf("the committed value needs to be < N") // TODO: boundary to be checked
		return nil, err
	}
	// c = g^a * h^r % group.N
	delta := group.N.BitLen() // length of N
	gamma := delta - 2
	// choose r from 2^(gamma + delta)
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(gamma+delta)), nil)
	r := common.GetRandomInt(b)

	tmp1 := group.Exp(committer.G, a)
	tmp2 := group.Exp(committer.H, r)
	c := group.Mul(tmp1, tmp2)

	committer.committedValue = a
	committer.r = r
	return c, nil
}

func (committer *DamgardFujisakiCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	return committer.committedValue, committer.r
}

type DamgardFujisakiReceiver struct {
	QRSpecialRSA *groups.QRSpecialRSA
	H            *big.Int
	G            *big.Int
	commitment   *big.Int
}

func NewDamgardFujisakiReceiver(safePrimeBitLength int) (*DamgardFujisakiReceiver, error) {
	qr, err := groups.NewQRSpecialRSA(safePrimeBitLength)
	if err != nil {
		return nil, err
	}

	h, err := qr.GetRandomGenerator()
	if err != nil {
		return nil, err
	}

	alpha := common.GetRandomInt(qr.Order)
	g := qr.Exp(h, alpha)
	if err != nil {
		return nil, err
	}

	return &DamgardFujisakiReceiver{
		QRSpecialRSA: qr,
		H:            h,
		G:            g,
	}, nil
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (receiver *DamgardFujisakiReceiver) SetCommitment(c *big.Int) {
	receiver.commitment = c
}

func (receiver *DamgardFujisakiReceiver) CheckDecommitment(r, a *big.Int) bool {
	tmp1 := receiver.QRSpecialRSA.Exp(receiver.G, a)
	tmp2 := receiver.QRSpecialRSA.Exp(receiver.H, r)
	c := receiver.QRSpecialRSA.Mul(tmp1, tmp2)

	return c.Cmp(receiver.commitment) == 0
}
