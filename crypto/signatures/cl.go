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

package signatures

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"

	"github.com/xlab-si/emmy/crypto/common"
)

type CL struct {
	// http://groups.csail.mit.edu/cis/pubs/lysyanskaya/cl02b.pdf
	numOfBlocks int
	config      *CLConfig
	p           *big.Int
	q           *big.Int
	pubKey      *CLPubKey
}

type CLSignature struct {
	e *big.Int
	s *big.Int
	v *big.Int
}

type CLConfig struct {
	l_n int
	l_m int
	l   int
}

type CLPubKey struct {
	n   *big.Int
	a_L []*big.Int
	b   *big.Int
	c   *big.Int
}

func NewCL(numOfBlocks int) *CL {
	config := CLConfig{
		l_n: 1024,
		l_m: 160,
		l:   160,
	}

	cl := CL{
		numOfBlocks: numOfBlocks,
		config:      &config,
	}
	cl.generateKey()
	return &cl
}

func NewPubCL(pubKey *CLPubKey) *CL {
	config := CLConfig{
		l_n: 1024,
		l_m: 160,
		l:   160,
	}

	cl := CL{
		config: &config,
		pubKey: pubKey,
	}

	return &cl
}

func (cl *CL) getQuadraticResidues(n *big.Int) ([]*big.Int, *big.Int, *big.Int) {
	var a_L []*big.Int
	for i := 0; i < cl.numOfBlocks; i++ {
		aRoot := common.GetRandomInt(n)
		a := new(big.Int).Mul(aRoot, aRoot)
		a.Mod(a, n)
		a_L = append(a_L, a)
	}

	bRoot := common.GetRandomInt(n)
	cRoot := common.GetRandomInt(n)
	b := new(big.Int).Mul(bRoot, bRoot)
	b.Mod(b, n)
	c := new(big.Int).Mul(cRoot, cRoot)
	c.Mod(c, n)

	return a_L, b, c
}

func (cl *CL) Sign(m_Ls []*big.Int) (*CLSignature, error) {
	if cl.numOfBlocks != len(m_Ls) {
		err := errors.New("the number of message blocks is not correct")
		return nil, err
	}

	// each m should be in [0, 2^l_m)
	for _, m_L := range m_Ls {
		if m_L.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cl.config.l_m)), nil)) > -1 {
			err := errors.New("msg is too big")
			return nil, err
		}
	}

	// choose a random prime number e > 2^(l_m+1) of length l_e = l_m + 2
	// that means: 2^(l_m+1) < e < 2^(l_m+2)
	e, _ := rand.Prime(rand.Reader, cl.config.l_m+2)

	b1 := e.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cl.config.l_m+1)), nil))
	b2 := e.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cl.config.l_m+2)), nil))
	if (b1 != 1) || (b2 != -1) {
		log.Panic("parameter not properly chosen")
	}

	s := common.GetRandomIntOfLength(cl.config.l_n + cl.config.l_m + cl.config.l)

	// v^e = a_1^m_1 * ... * a_L^m_L * b^s * c % n

	a := new(big.Int)
	for i := 0; i < cl.numOfBlocks; i++ {
		a = new(big.Int).Exp(cl.pubKey.a_L[i], m_Ls[i], cl.pubKey.n)
	}

	t2 := new(big.Int).Exp(cl.pubKey.b, s, cl.pubKey.n) // b^s (mod n)
	t := new(big.Int).Mul(a, t2)                        // a_1^m_1 * ... * a_L^m_L * b^s (mod n)
	t = new(big.Int).Mul(t, cl.pubKey.c)
	t = new(big.Int).Mod(t, cl.pubKey.n)

	pMin1 := new(big.Int).Sub(cl.p, big.NewInt(1))
	qMin1 := new(big.Int).Sub(cl.q, big.NewInt(1))
	phi_n := new(big.Int).Mul(pMin1, qMin1) // how many invertible elements in Z_n (used for Euler's theorem)

	eInv := new(big.Int).ModInverse(e, phi_n)

	// now we have: e*eInv = 1 (mod phi_n),
	// which means there exists k such that: e*eInv = k*phi_n + 1
	// v can be calculated as (modulus is omitted):
	// v^(e*eInv) = v^(k*phi_n+1) = v^(k*phi_n) * v = v,
	// because v^(k*phi_n) = (v^phi_n)^k = 1^k = 1 due to Euler's theorem
	v := new(big.Int).Exp(t, eInv, cl.pubKey.n)

	signature := CLSignature{
		e: e,
		s: s,
		v: v,
	}

	return &signature, nil
}

func (cl *CL) Verify(m_Ls []*big.Int, signature *CLSignature) (bool, error) {
	// each m should be in [0, 2^l_m)
	for _, m_L := range m_Ls {
		if m_L.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cl.config.l_m)), nil)) > -1 {
			err := errors.New("msg is too big")
			return false, err
		}
	}

	// check v^e = a^m*b^s*c (mod n)
	// and check: 2^l_e - 1 < e < 2^l_e, where l_e = l_m + 2

	/*
		b1 := signature.e.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cl.config.l_m+1)), nil))
		b2 := signature.e.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cl.config.l_m+2)), nil))
		if (b1 != 1) || (b2 != -1) {
			return false, nil
		}
	*/

	numOfBlocks := len(m_Ls)
	a := new(big.Int)
	for i := 0; i < numOfBlocks; i++ {
		a = new(big.Int).Exp(cl.pubKey.a_L[i], m_Ls[i], cl.pubKey.n)
	}

	t2 := new(big.Int).Exp(cl.pubKey.b, signature.s, cl.pubKey.n) // b^s
	t := new(big.Int).Mul(a, t2)
	t = new(big.Int).Mul(t, cl.pubKey.c) // a^m * b^s * c
	t = new(big.Int).Mod(t, cl.pubKey.n) // a^m * b^s * c % n

	ve := new(big.Int).Exp(signature.v, signature.e, cl.pubKey.n) // v^e
	ve = new(big.Int).Mod(ve, cl.pubKey.n)                        // v^e % n
	return ve.Cmp(t) == 0, nil
}

func (cl *CL) GetPubKey() *CLPubKey {
	return cl.pubKey
}

func (cl *CL) generateKey() (err error) {
	// generate two primes of length 512
	p, err := common.GetSafePrime(512)
	q, err := common.GetSafePrime(512)
	if err != nil {
		return err
	}
	n := new(big.Int).Mul(p, q)
	a_L, b, c := cl.getQuadraticResidues(n)
	cl.p = p
	cl.q = q
	cl.pubKey = &CLPubKey{
		n:   n,
		a_L: a_L,
		b:   b,
		c:   c,
	}
	return nil
}
