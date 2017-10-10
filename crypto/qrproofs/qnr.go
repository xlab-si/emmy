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

package qrproofs

// Statistical zero-knowledge proof of quadratic non-residousity (implemented for historical
// reasons).

import (
	"errors"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/types"
	"math/big"
)

func QNR(y *big.Int, qr *dlog.QR) (bool, error) {
	prover := NewQNRProver(qr, y)
	verifier := NewQNRVerifier(qr, y)
	m := qr.N.BitLen()

	for i := 0; i < m; i++ {
		w, pairs := verifier.GetChallenge()
		prover.SetProofRandomData(w)
		// get challenge from prover for proving that verifier is not cheating
		randVector := prover.GetChallenge()

		verProof := verifier.GetProofData(randVector)

		verifierIsHonest := prover.Verify(pairs, verProof)
		if !verifierIsHonest {
			err := errors.New("verifier is not honest")
			return false, err
		}

		typ, err := prover.GetProofData(w)
		if err != nil {
			return false, nil
		}

		proved := verifier.Verify(typ)
		if proved == false {
			return false, nil
		}
	}
	return true, nil
}

type QNRProver struct {
	QR *dlog.QR
	Y  *big.Int
	w  *big.Int
}

func NewQNRProver(qr *dlog.QR, y *big.Int) *QNRProver {
	return &QNRProver{
		QR: qr,
		Y:  y,
	}
}

func (prover *QNRProver) GetChallenge() []int {
	m := prover.QR.N.BitLen()
	var randVector []int
	for i := 0; i < m; i++ {
		// todo: remove big.Int
		b := common.GetRandomInt(big.NewInt(2)) // 0 or 1
		var r int
		if b.Cmp(big.NewInt(0)) == 0 {
			r = 0
		} else {
			r = 1
		}
		randVector = append(randVector, r)
	}
	return randVector
}

func (prover *QNRProver) SetProofRandomData(w *big.Int) {
	prover.w = w
}

func (prover *QNRProver) GetProofData(challenge *big.Int) (int, error) {
	isQR, err := prover.QR.IsQR(challenge)
	if err != nil {
		return 0, err
	}
	var typ int
	if isQR {
		typ = 1 // challenge is of type r^2
	} else {
		typ = 2 // challenge is of type r^2 * y
	}
	return typ, nil
}

func (prover *QNRProver) Verify(pairs, verProof []*types.Pair) bool {
	for ind, proofPair := range verProof {
		if proofPair.B.Cmp(big.NewInt(0)) == 0 {
			t := prover.QR.Multiply(proofPair.A, proofPair.A)
			Aw := prover.QR.Multiply(pairs[ind].A, prover.w)
			Bw := prover.QR.Multiply(pairs[ind].B, prover.w)

			if (t.Cmp(Aw) != 0) && (t.Cmp(Bw) != 0) {
				return false
			}
		} else {
			r1Squared := prover.QR.Multiply(proofPair.A, proofPair.A)
			r2Squared := prover.QR.Multiply(proofPair.B, proofPair.B)
			r2Squaredy := prover.QR.Multiply(r2Squared, prover.Y)
			pair := pairs[ind]

			if !((r1Squared.Cmp(pair.A) == 0 && r2Squaredy.Cmp(pair.B) == 0) ||
				(r1Squared.Cmp(pair.B) == 0 && r2Squaredy.Cmp(pair.A) == 0)) {
				return false
			}
		}
	}
	return true
}

type QNRVerifier struct {
	QR    *dlog.QR
	x     *big.Int
	y     *big.Int
	typ   int
	r     *big.Int
	pairs []*types.Pair
}

func NewQNRVerifier(qr *dlog.QR, y *big.Int) *QNRVerifier {
	return &QNRVerifier{
		QR: qr,
		y:  y,
	}
}

func (verifier *QNRVerifier) GetChallenge() (*big.Int, []*types.Pair) {
	r := common.GetRandomInt(verifier.QR.N)
	// checking that gcd(r, N) = 1 is not needed as the probability is low
	verifier.r = r
	verifier.pairs = verifier.pairs[:0] // clear verifier.pairs
	r2 := verifier.QR.Multiply(r, r)

	b := common.GetRandomInt(big.NewInt(2)) // 0 or 1
	var w *big.Int

	if b.Cmp(big.NewInt(0)) == 0 {
		w = r2
		verifier.typ = 1
	} else {
		w = verifier.QR.Multiply(r2, verifier.y)
		verifier.typ = 2
	}

	m := verifier.QR.N.BitLen()
	var pairs []*types.Pair
	for i := 0; i < m; i++ {
		r1 := common.GetRandomInt(verifier.QR.N)
		r2 := common.GetRandomInt(verifier.QR.N)
		aj := verifier.QR.Multiply(r1, r1) // r1^2
		bj := verifier.QR.Multiply(r2, r2)
		bj = verifier.QR.Multiply(bj, verifier.y) // r2^2 * y

		bitj := common.GetRandomInt(big.NewInt(2)) // 0 or 1

		verifier.pairs = append(verifier.pairs, &types.Pair{A: r1, B: r2})

		var pair *types.Pair
		if bitj.Cmp(big.NewInt(1)) == 0 {
			pair = &types.Pair{
				A: aj,
				B: bj,
			}
		} else {
			pair = &types.Pair{
				A: bj,
				B: aj,
			}
		}
		pairs = append(pairs, pair)
	}

	return w, pairs
}

func (verifier *QNRVerifier) GetProofData(randVector []int) []*types.Pair {
	var pairs []*types.Pair
	for ind, i := range randVector {
		if i == 0 {
			pair := &types.Pair{
				A: verifier.pairs[ind].A,
				B: verifier.pairs[ind].B,
			}
			pairs = append(pairs, pair)
		} else {
			if verifier.typ == 1 { // w = r^2
				r1 := verifier.pairs[ind].A
				t := verifier.QR.Multiply(verifier.r, r1)
				// t = r * r1
				pairs = append(pairs, &types.Pair{A: t, B: big.NewInt(0)})
			} else { // w = r^2 * y
				r2 := verifier.pairs[ind].B
				t := verifier.QR.Multiply(verifier.r, r2)
				t = verifier.QR.Multiply(t, verifier.y)
				// t = r * r2 * y
				pairs = append(pairs, &types.Pair{A: t, B: big.NewInt(0)})
			}
		}
	}
	return pairs
}

func (verifier *QNRVerifier) Verify(typ int) bool {
	if verifier.typ == typ {
		return true
	} else {
		return false
	}
}
