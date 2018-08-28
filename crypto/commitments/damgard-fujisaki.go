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
	"github.com/xlab-si/emmy/crypto/qr"
)

// Based on:
// I. Damgard and E. Fujisaki. An integer commitment scheme based on groups with hidden order. http://eprint.iacr.org/2001, 2001.
//
// Damgard-Fujisaki is statistically-hiding integer commitment scheme which works in groups
// with hidden order, like RSASpecial.
// This scheme can be used to commit to any integer (that is not generally true for commitment
// schemes, usually there is some boundary), however a boundary (denoted by T) is needed
// for the associated proofs.

// DamgardFujisaki presents what is common in DamgardFujisakiCommitter and DamgardFujisakiReceiver.
type damgardFujisaki struct {
	QRSpecialRSA *qr.RSASpecial
	H            *big.Int
	G            *big.Int // G = H^alpha % RSASpecial.N, where alpha is chosen when Receiver is created (Committer does not know alpha)
	K            int      // security parameter
}

// ComputeCommit returns G^a * H^r % group.N for a given a and r. Note that this is exactly
// the commitment, but with a given a and r. It serves as a helper function for
// associated proofs where g^x * h^y % group.N needs to be computed several times.
func (df *damgardFujisaki) ComputeCommit(a, r *big.Int) *big.Int {
	tmp1 := df.QRSpecialRSA.Exp(df.G, a)
	tmp2 := df.QRSpecialRSA.Exp(df.H, r)
	c := df.QRSpecialRSA.Mul(tmp1, tmp2)
	return c
}

type DamgardFujisakiCommitter struct {
	damgardFujisaki
	B              int      // 2^B is upper bound estimation for group order, it can be len(RSASpecial.N) - 2
	T              *big.Int // we can commit to values between -T and T
	committedValue *big.Int
	r              *big.Int
}

// TODO: switch h and g
func NewDamgardFujisakiCommitter(n, g, h, t *big.Int, k int) *DamgardFujisakiCommitter {
	// n.BitLen() - 2 is used as B
	return &DamgardFujisakiCommitter{damgardFujisaki: damgardFujisaki{
		QRSpecialRSA: qr.NewRSApecialPublic(n),
		G:            g,
		H:            h,
		K:            k},
		B: n.BitLen() - 2,
		T: t}
}

// TODO: the naming is not OK because it also sets committer.committedValue and committer.r
func (committer *DamgardFujisakiCommitter) GetCommitMsg(a *big.Int) (*big.Int, error) {
	abs := new(big.Int).Abs(a)
	if abs.Cmp(committer.T) != -1 {
		return nil, fmt.Errorf("committed value needs to be in (-T, T)")
	}
	// c = G^a * H^r % group.N
	// choose r from 2^(B + k)
	exp := big.NewInt(int64(committer.B + committer.K))
	boundary := new(big.Int).Exp(big.NewInt(2), exp, nil)
	r := common.GetRandomInt(boundary)
	c := committer.ComputeCommit(a, r)

	committer.committedValue = a
	committer.r = r
	return c, nil
}

func (committer *DamgardFujisakiCommitter) GetCommitMsgWithGivenR(a, r *big.Int) (*big.Int, error) {
	abs := new(big.Int).Abs(a)
	if abs.Cmp(committer.T) != -1 {
		return nil, fmt.Errorf("committed value needs to be in (-T, T)")
	}
	// c = G^a * H^r % group.N
	c := committer.ComputeCommit(a, r)
	committer.committedValue = a
	committer.r = r
	return c, nil
}

func (committer *DamgardFujisakiCommitter) GetDecommitMsg() (*big.Int, *big.Int) {
	return committer.committedValue, committer.r
}

type DamgardFujisakiReceiver struct {
	damgardFujisaki
	Commitment *big.Int
}

// NewDamgardFujisakiReceiver receives two parameters: safePrimeBitLength tells the length of the
// primes in RSASpecial group and should be at least 1024, k is security parameter on which it depends
// the hiding property (commitment c = G^a * H^r where r is chosen randomly from (0, 2^(B+k)) - the distribution of
// c is statistically close to uniform, 2^B is upper bound estimation for group order).
func NewDamgardFujisakiReceiver(safePrimeBitLength, k int) (*DamgardFujisakiReceiver, error) {
	qr, err := qr.NewRSASpecial(safePrimeBitLength)
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

	return &DamgardFujisakiReceiver{damgardFujisaki: damgardFujisaki{
			QRSpecialRSA: qr,
			H:            h,
			G:            g,
			K:            k}},
		nil
}

// NewDamgardFujisakiReceiverFromParams returns an instance of a receiver with the
// parameters as given by input. Different instances are needed because
// each sets its own Commitment value.
func NewDamgardFujisakiReceiverFromParams(specialRSAPrimes *qr.RSASpecialPrimes, g, h *big.Int,
	k int) (
	*DamgardFujisakiReceiver, error) {
	group, err := qr.NewRSASpecialFromParams(specialRSAPrimes)
	if err != nil {
		return nil, err
	}

	return &DamgardFujisakiReceiver{damgardFujisaki: damgardFujisaki{
		QRSpecialRSA: group,
		G:            g,
		H:            h,
		K:            k},
	}, nil
}

// When receiver receives a commitment, it stores the value using SetCommitment method.
func (receiver *DamgardFujisakiReceiver) SetCommitment(c *big.Int) {
	receiver.Commitment = c
}

func (receiver *DamgardFujisakiReceiver) CheckDecommitment(r, a *big.Int) bool {
	tmp1 := receiver.QRSpecialRSA.Exp(receiver.G, a)
	tmp2 := receiver.QRSpecialRSA.Exp(receiver.H, r)
	c := receiver.QRSpecialRSA.Mul(tmp1, tmp2)

	return c.Cmp(receiver.Commitment) == 0
}
