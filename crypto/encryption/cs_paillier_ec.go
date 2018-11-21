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

package encryption

import (
	"fmt"
	"log"
	"math/big"

	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/qr"
)

type Point struct {
	X big.Int
	Y big.Int
}

func pt(x, y *big.Int) Point {
	return Point{
		X: *x,
		Y: *y,
	}
}

// todo: does hash really need to be into [0, 2^l]?

// CSPaillierEC represents Camenisch-Shoup variant of Paillier to make it (Paillier) CCA2 secure.
// http://eprint.iacr.org/2002/161.pdf
type CSPaillierEC struct {
	SecParams *CSPaillierECSecParams
	n1        *big.Int // n'
	PubKey    *CSPaillierECPubKey
	SecKey    *CSPaillierECSecKey
	// verifierRandomData: encryptor stores s, r1, s1, m1;
	verifierRandomData *CSPaillierECVerifierRandomData
	// proverRandomData stores c, u1, e1, v1, delta1, l1
	proverRandomData *CSPaillierECProverRandomData
	proverEncData    *CSPaillierECProverEncData
	verifierEncData  *CSPaillierECVerifierEncData
}

type CSPaillierECSecParams struct {
	L        int // length of p1 and q1 (l in a paper)
	RoLength int // ro is order of cyclic group Gamma (used for discrete logarithm)
	K        int // k in a paper; it must hold 2**K < min{p1, q1, ro}
	K1       int // k' in a paper; it must hold ro * 2**(K + K1 + 3) < n
	// lambda *big.Int // security parameters are function of lambda in a paper
}

type CSPaillierECSecKey struct {
	N  *big.Int
	G  *big.Int
	X1 *big.Int
	X2 *big.Int
	X3 *big.Int
	// the parameters below are for verifiable encryption
	Gamma                *secp256k1.KoblitzCurve // for discrete logarithm
	VerifiableEncGroupN  *big.Int
	VerifiableEncGroupG1 *big.Int
	VerifiableEncGroupH1 *big.Int
	K                    int
	K1                   int
}

// CSPaillierECPubKey currently does not use auxiliary parameters/primes - no additional n, p,
// q parameters
// (as specified in a paper, original n, p, q can be used).
type CSPaillierECPubKey struct {
	N  *big.Int
	G  *big.Int
	Y1 *big.Int
	Y2 *big.Int
	Y3 *big.Int
	// the parameters below are for verifiable encryption
	Gamma                *secp256k1.KoblitzCurve // for discrete logarithm
	VerifiableEncGroupN  *big.Int
	VerifiableEncGroupG1 *big.Int
	VerifiableEncGroupH1 *big.Int
	K                    int
	K1                   int
}

type CSPaillierECProverRandomData struct {
	S  *big.Int
	R1 *big.Int
	S1 *big.Int
	M1 *big.Int
}

type CSPaillierECVerifierRandomData struct {
	L      *big.Int
	U1     *big.Int
	E1     *big.Int
	V1     *big.Int
	Delta1 *Point
	L1     *big.Int
	C      *big.Int
}

type CSPaillierECProverEncData struct {
	R *big.Int
	M *big.Int
}

type CSPaillierECVerifierEncData struct {
	U     *big.Int
	E     *big.Int
	V     *big.Int
	Label *big.Int
	Delta *Point
}

func NewCSPaillierEC(secParams *CSPaillierECSecParams) *CSPaillierEC {
	cspaillier := CSPaillierEC{
		SecParams: secParams,
	}
	cspaillier.generateKey()

	return &cspaillier
}

func NewCSPaillierECFromSecKey(secKey *CSPaillierECSecKey) (*CSPaillierEC, error) {
	return &CSPaillierEC{
		SecKey: secKey,
		PubKey: &CSPaillierECPubKey{ // Abs is used also in decrypt where PubKey is called
			N: secKey.N,
		},
	}, nil
}

func NewCSPaillierECFromPubKey(pubKey *CSPaillierECPubKey) *CSPaillierEC {
	return &CSPaillierEC{
		PubKey: pubKey,
	}
}

// Returns (u, e, v).
func (csp *CSPaillierEC) Encrypt(m, label *big.Int) (*big.Int, *big.Int, *big.Int, error) {
	if m.Cmp(csp.PubKey.N) >= 0 {
		err := fmt.Errorf("msg is too big")
		return nil, nil, nil, err
	}

	b := new(big.Int).Div(csp.PubKey.N, big.NewInt(4))
	r := common.GetRandomInt(b)

	n2 := new(big.Int).Mul(csp.PubKey.N, csp.PubKey.N)
	// u = g^r
	u := new(big.Int).Exp(csp.PubKey.G, r, n2)

	// e = y1^r * h^m
	e1 := new(big.Int).Exp(csp.PubKey.Y1, r, n2)       // y1^r
	h := new(big.Int).Add(csp.PubKey.N, big.NewInt(1)) // 1 + n
	e2 := new(big.Int).Exp(h, m, n2)                   // h^m

	e := new(big.Int).Mul(e1, e2) // y1^r * h^m
	e.Mod(e, n2)

	// v = abs((y2 * y3^hash(u, e, L))^r)
	hashNum := common.Hash(u, e, label)

	t := new(big.Int).Exp(csp.PubKey.Y3, hashNum, n2) // y3^hashNum
	t.Mul(csp.PubKey.Y2, t)                           // y2 * y3^hashNum
	t.Exp(t, r, n2)                                   // (y2 * y3^hashNum)^r

	v, _ := csp.Abs(t)

	csp.proverEncData = &CSPaillierECProverEncData{
		R: r,
		M: m,
	}

	return u, e, v, nil
}

func (csp *CSPaillierEC) Decrypt(u, e, v, label *big.Int) (*big.Int, error) {
	// check whether Abs(v) = v:
	vAbs, _ := csp.Abs(v)
	if v.Cmp(vAbs) != 0 {
		err := fmt.Errorf("v != abs(v)")
		return nil, err
	}

	// check whether u^(2 * (x2 + hash(u, e, L) * x3)) = v^2:
	// hash(u, e, L)
	hashNum := common.Hash(u, e, label)

	// hash(u, e, L) * x3
	t := new(big.Int).Mul(hashNum, csp.SecKey.X3)

	// x2 + hash(u, e, L) * x3:
	t.Add(csp.SecKey.X2, t)
	t.Mul(t, big.NewInt(2))

	n2 := new(big.Int).Mul(csp.PubKey.N, csp.PubKey.N)
	t.Exp(u, t, n2)
	t.Mod(t, n2)

	v2 := new(big.Int).Mul(v, v)
	v2.Mod(v2, n2)

	if t.Cmp(v2) != 0 {
		err := fmt.Errorf("CSPaillierEC decryption failed 1")
		return nil, err
	}

	// check whether m1 is of the form h^m for some m from Z_n (meaning m1 = 1 + m * n)
	ux1 := new(big.Int).Exp(u, csp.SecKey.X1, n2) // u^x1
	ux1Inv := new(big.Int).ModInverse(ux1, n2)    // u^x1_inv

	m1 := new(big.Int).Mul(e, ux1Inv)
	m1.Mod(m1, n2)

	m1min := new(big.Int).Sub(m1, big.NewInt(1))
	m1minModulo := new(big.Int).Mod(m1min, csp.PubKey.N)

	if m1minModulo.Cmp(big.NewInt(0)) != 0 {
		err := fmt.Errorf("CSPaillierEC decryption failed 2")
		return nil, err
	}

	m := new(big.Int).Div(m1min, csp.PubKey.N)

	return m, nil
}

func (csp *CSPaillierEC) Abs(a *big.Int) (*big.Int, error) {
	n2 := new(big.Int).Mul(csp.PubKey.N, csp.PubKey.N)
	if a.Cmp(n2) >= 0 {
		err := fmt.Errorf("value is too big for abs function")
		return nil, err
	}
	b := new(big.Int).Div(n2, big.NewInt(2))
	if a.Cmp(b) <= 0 {
		return a, nil
	} else {
		t := new(big.Int).Sub(n2, a) // n^2 - a
		return t, nil
	}
}

func (csp *CSPaillierEC) generateKey() {
	p1 := common.GetGermainPrime(csp.SecParams.L)
	q1 := common.GetGermainPrime(csp.SecParams.L)

	p := new(big.Int).Add(p1, p1)
	p.Add(p, big.NewInt(1))

	q := new(big.Int).Add(q1, q1)
	q.Add(q, big.NewInt(1))

	//csp.lambda = common.LCM(p_min, q_min)
	n := new(big.Int).Mul(p, q)
	csp.n1 = new(big.Int).Mul(p1, q1)
	n2 := new(big.Int).Mul(n, n)

	pubKey := CSPaillierECPubKey{
		N: n,
	}

	// for verifiable encryption:
	// Gamma, err := schnorr.NewGroup(csp.SecParams.RoLength)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	Gamma := secp256k1.S256()
	pubKey.Gamma = Gamma

	// it must hold:
	// 2**K < min{p1, q1, ro}; ro is Gamma.N
	// ro * 2**(K + K1 + 3) < n

	check1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(csp.SecParams.K)), nil)
	if check1.Cmp(p1) >= 0 || check1.Cmp(q1) >= 0 || check1.Cmp(Gamma.N) >= 0 {
		log.Fatal("Does not pass check 1: 2**K < min{p1, q1, ro}; ro is Gamma.N")
	}

	tmp := csp.SecParams.K + csp.SecParams.K1 + 3
	check2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(tmp)), nil)
	check2.Mul(check2, Gamma.N)

	if check2.Cmp(n) >= 0 {
		log.Fatal("Does not pass check 2: N < n2**(-K-K1-3)")
	}

	pubKey.K = csp.SecParams.K
	pubKey.K1 = csp.SecParams.K1

	// Now we need to compute two generators in Z_n* subgroup of order n1.
	// Note that here a different n might be used from the one in encryption,
	// however as above we assume the same (the paper says it can be the same).

	primes := qr.NewRSASpecialPrimes(p, q, p1, q1)
	verifiableEncGroup, err := NewVerifiableEncGroupEC(primes)
	if err != nil {
		log.Fatal(err)
	}

	pubKey.VerifiableEncGroupN = verifiableEncGroup.N
	pubKey.VerifiableEncGroupG1 = verifiableEncGroup.G1
	pubKey.VerifiableEncGroupH1 = verifiableEncGroup.H1

	secretKey := CSPaillierECSecKey{
		N:  n,
		K:  csp.SecParams.K,
		K1: csp.SecParams.K1,
	}
	secretKey.Gamma = Gamma
	secretKey.VerifiableEncGroupN = verifiableEncGroup.N
	secretKey.VerifiableEncGroupG1 = verifiableEncGroup.G1
	secretKey.VerifiableEncGroupH1 = verifiableEncGroup.H1

	// choose x1, x2, x3 which are < n^2/4
	b := new(big.Int).Div(n2, big.NewInt(4))
	secretKey.X1 = common.GetRandomInt(b)
	secretKey.X2 = common.GetRandomInt(b)
	secretKey.X3 = common.GetRandomInt(b)

	for { // choose g1 from Z_n^2*
		g1 := common.GetRandomInt(n2)
		gcd := new(big.Int).GCD(nil, nil, g1, n2) // negligible probability that gcd != 1
		if gcd.Cmp(big.NewInt(1)) == 0 {
			t := new(big.Int).Mul(big.NewInt(2), n)
			g := new(big.Int).Exp(g1, t, n2)
			pubKey.G = g
			secretKey.G = g
			break
		}
	}

	pubKey.Y1 = new(big.Int).Exp(pubKey.G, secretKey.X1, n2)
	pubKey.Y2 = new(big.Int).Exp(pubKey.G, secretKey.X2, n2)
	pubKey.Y3 = new(big.Int).Exp(pubKey.G, secretKey.X3, n2)
	csp.PubKey = &pubKey
	csp.SecKey = &secretKey
}

// Returns l = g1^m * h1^s where s is a random integer smaller than n/4.
func (csp *CSPaillierEC) GetOpeningMsg(m *big.Int) (*big.Int, *Point) {
	b := new(big.Int).Div(csp.PubKey.VerifiableEncGroupN, big.NewInt(4))
	s := common.GetRandomInt(b)

	t1 := new(big.Int).Exp(csp.PubKey.VerifiableEncGroupG1, m,
		csp.PubKey.VerifiableEncGroupN)
	t2 := new(big.Int).Exp(csp.PubKey.VerifiableEncGroupH1, s,
		csp.PubKey.VerifiableEncGroupN)
	l := new(big.Int).Mul(t1, t2)
	l.Mod(l, csp.PubKey.VerifiableEncGroupN)

	csp.proverRandomData = &CSPaillierECProverRandomData{
		S: s,
	}

	// delta := new(big.Int).Exp(csp.PubKey.Gamma.G, m, csp.PubKey.Gamma.P)
	delta := pt(csp.PubKey.Gamma.ScalarBaseMult(m.Bytes()))
	return l, &delta
}

// Prover (encryptor) should use this function to generate values for the first sigma protocol message.
func (csp *CSPaillierEC) GetProofRandomData(u, e, label *big.Int) (*big.Int, *big.Int,
	*big.Int, *Point, *big.Int, error) {
	two := big.NewInt(2)
	t1 := new(big.Int).Exp(two, big.NewInt(int64(csp.PubKey.K+csp.PubKey.K1-2)), nil)
	b1 := new(big.Int).Mul(csp.PubKey.N, t1)
	r1, err := common.GetRandomIntFromRange(new(big.Int).Neg(b1), b1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	b2 := new(big.Int).Mul(csp.PubKey.VerifiableEncGroupN, t1)
	s1, err := common.GetRandomIntFromRange(new(big.Int).Neg(b2), b2)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	t2 := new(big.Int).Exp(two, big.NewInt(int64(csp.PubKey.K+csp.PubKey.K1)), nil)
	b3 := new(big.Int).Mul(csp.PubKey.Gamma.N, t2)
	m1, err := common.GetRandomIntFromRange(new(big.Int).Neg(b3), b3)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	n2 := new(big.Int).Mul(csp.PubKey.N, csp.PubKey.N)

	// u1 = g^(2*r1)
	u1 := common.Exponentiate(csp.PubKey.G, new(big.Int).Mul(big.NewInt(2), r1), n2)

	// e1 = y1^(2*r1) * h^(2*m1)
	h := new(big.Int).Add(csp.PubKey.N, big.NewInt(1)) // 1 + n
	e1Part1 := common.Exponentiate(csp.PubKey.Y1, new(big.Int).Mul(big.NewInt(2), r1), n2)
	e1Part2 := common.Exponentiate(h, new(big.Int).Mul(big.NewInt(2), m1), n2)
	e1 := new(big.Int).Mul(e1Part1, e1Part2)
	e1.Mod(e1, n2)

	// v1 = (y2 * y3^hash(u, e, L))^(2*r1)
	hashNum := common.Hash(u, e, label)
	v11 := new(big.Int).Exp(csp.PubKey.Y3, hashNum, n2)
	v11.Mul(v11, csp.PubKey.Y2)
	v11.Mod(v11, n2)
	v1 := common.Exponentiate(v11, new(big.Int).Mul(big.NewInt(2), r1), n2)

	// delta1 = gamma^m1
	// delta1 := common.Exponentiate(csp.PubKey.Gamma.G, m1,
	// 	csp.PubKey.Gamma.P)
	delta1 := pt(csp.PubKey.Gamma.ScalarBaseMult(m1.Bytes()))

	// l1 = g1^m1 * h1^s1
	l11 := common.Exponentiate(csp.PubKey.VerifiableEncGroupG1, m1,
		csp.PubKey.VerifiableEncGroupN)
	l12 := common.Exponentiate(csp.PubKey.VerifiableEncGroupH1, s1,
		csp.PubKey.VerifiableEncGroupN)
	l1 := new(big.Int).Mul(l11, l12)
	l1.Mod(l1, csp.PubKey.VerifiableEncGroupN)

	csp.proverRandomData.R1 = r1
	csp.proverRandomData.S1 = s1
	csp.proverRandomData.M1 = m1
	return u1, e1, v1, &delta1, l1, nil
}

// Prover should use this function to compute data for second (last) sigma protocol message.
func (csp *CSPaillierEC) GetProofData(c *big.Int) (*big.Int, *big.Int, *big.Int) {
	// rTilde = r1 - c * r
	t := new(big.Int).Mul(c, csp.proverEncData.R)
	rTilde := new(big.Int).Sub(csp.proverRandomData.R1, t)

	// sTilde = s1 - c * s
	t.Mul(c, csp.proverRandomData.S)
	sTilde := new(big.Int).Sub(csp.proverRandomData.S1, t)

	// mTilde = m1 - c * m
	// t.Mul(c, csp.proverEncData.M)
	mTilde := new(big.Int).Sub(csp.proverRandomData.M1, new(big.Int).Mul(c, csp.proverEncData.M))
	return rTilde, sTilde, mTilde
}

// Verifier should call this function when it receives l = g1^m * h1^s as the first protocol message.
func (csp *CSPaillierEC) SetVerifierEncData(u, e, v *big.Int, delta Point, label, l *big.Int) {
	csp.verifierRandomData = &CSPaillierECVerifierRandomData{
		L: l,
	}
	csp.verifierEncData = &CSPaillierECVerifierEncData{
		U:     u,
		E:     e,
		V:     v,
		Label: label,
		Delta: &delta,
	}
}

func (csp *CSPaillierEC) Verify(rTilde, sTilde, mTilde *big.Int) bool {
	// u1 = csp.verifierRandomData.U1
	// u = csp.verifierEncData.U
	// c = csp.verifierRandomData.C
	// g = csp.PubKey.G

	// check if u1 = u^(2*c) * g^(2*rTilde)
	n2 := new(big.Int).Mul(csp.PubKey.N, csp.PubKey.N)
	twoC := new(big.Int).Mul(csp.verifierRandomData.C, big.NewInt(2))
	twoRTilde := new(big.Int).Mul(rTilde, big.NewInt(2))

	t1 := common.Exponentiate(csp.verifierEncData.U, twoC, n2)
	t2 := common.Exponentiate(csp.PubKey.G, twoRTilde, n2)
	t := new(big.Int).Mul(t1, t2)
	t.Mod(t, n2)
	if csp.verifierRandomData.U1.Cmp(t) != 0 {
		log.Println("NOT OK 1")
		return false
	}

	// check if e1 = e^(2*c) * y1^(2*rTilde) * h^(2*mTilde)
	t1 = common.Exponentiate(csp.verifierEncData.E, twoC, n2)
	y1 := new(big.Int).Mod(csp.PubKey.Y1, n2)
	t2 = common.Exponentiate(y1, twoRTilde, n2)
	h := new(big.Int).Add(csp.PubKey.N, big.NewInt(1)) // 1 + n
	t3 := common.Exponentiate(h, new(big.Int).Mul(big.NewInt(2), mTilde), n2)
	t.Mul(t1, t2)
	t.Mul(t, t3)
	t.Mod(t, n2)
	if csp.verifierRandomData.E1.Cmp(t) != 0 {
		log.Println("NOT OK 2")
		return false
	}

	// check if v1 = v^(2*c) * (y2 * y3^hash(u, e, L))^(2*rTilde)
	t1 = common.Exponentiate(csp.verifierEncData.V, twoC, n2)
	hashNum := common.Hash(csp.verifierEncData.U, csp.verifierEncData.E,
		csp.verifierEncData.Label)
	y3 := new(big.Int).Mod(csp.PubKey.Y3, n2)
	t21 := new(big.Int).Exp(y3, hashNum, n2)
	y2 := new(big.Int).Mod(csp.PubKey.Y2, n2)
	t21.Mul(y2, t21)
	t2 = common.Exponentiate(t21, twoRTilde, n2)
	t.Mul(t1, t2)
	t.Mod(t, n2)
	if csp.verifierRandomData.V1.Cmp(t) != 0 {
		log.Println("NOT OK 3")
		return false
	}

	// check if delta1 = delta^c * Gamma.G^mTilde
	// t1.Exp(csp.verifierEncData.Delta, csp.verifierRandomData.C,
	// 	csp.PubKey.Gamma.P)
	deltac := pt(csp.PubKey.Gamma.ScalarMult(&csp.verifierEncData.Delta.X, &csp.verifierEncData.Delta.Y, csp.verifierRandomData.C.Bytes()))
	// t1 = new(big.Int).Mod(&tmp1.X, csp.PubKey.Gamma.P)
	// t2 = common.Exponentiate(csp.PubKey.Gamma.G, mTilde, csp.PubKey.Gamma.P)
	gmtilde := pt(csp.PubKey.Gamma.ScalarBaseMult(new(big.Int).Mod(mTilde, csp.PubKey.Gamma.N).Bytes()))
	// t2 = new(big.Int).Mod(&tmp2.X, csp.PubKey.Gamma.P)
	// t.Mul(t1, t2)
	tmpt := pt(csp.PubKey.Gamma.Add(&deltac.X, &deltac.Y, &gmtilde.X, &gmtilde.Y))
	t.Mod(&tmpt.X, csp.PubKey.Gamma.P)
	delta1X := new(big.Int).Mod(&csp.verifierRandomData.Delta1.X, csp.PubKey.Gamma.P)
	if delta1X.Cmp(&tmpt.X) != 0 {
		log.Println("NOT OK 4")
		return false
	}

	// check if l1 = l^c * g1^mTilde * h1^sTilde
	t1.Exp(csp.verifierRandomData.L, csp.verifierRandomData.C, n2)
	t2 = common.Exponentiate(csp.PubKey.VerifiableEncGroupG1,
		mTilde, csp.PubKey.VerifiableEncGroupN)
	t3 = common.Exponentiate(csp.PubKey.VerifiableEncGroupH1,
		sTilde, csp.PubKey.VerifiableEncGroupN)
	t.Mul(t1, t2)
	t.Mul(t, t3)
	t.Mod(t, csp.PubKey.VerifiableEncGroupN)
	if csp.verifierRandomData.L1.Cmp(t) != 0 {
		log.Println("NOT OK 5")
		return false
	}

	// check if -n/4 < mTilde < n/4
	b := new(big.Int).Div(csp.PubKey.N, big.NewInt(4))
	if new(big.Int).Abs(mTilde).Cmp(b) >= 0 {
		log.Println("NOT OK 6")
		return false
	}

	return true
}

func (csp *CSPaillierEC) GetChallenge() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(csp.PubKey.K)), nil)
	c := common.GetRandomInt(b)
	return c
}

// Verifier should call this function when it receives proof random data as the second protocol message.
func (csp *CSPaillierEC) SetProofRandomData(u1, e1, v1 *big.Int, delta1 Point, l1, c *big.Int) {
	csp.verifierRandomData.U1 = u1
	csp.verifierRandomData.E1 = e1
	csp.verifierRandomData.V1 = v1
	csp.verifierRandomData.Delta1 = &delta1
	csp.verifierRandomData.L1 = l1
	csp.verifierRandomData.C = c
}

type VerifiableEncGroupEC struct {
	*qr.RSASpecial
	G1 *big.Int
	H1 *big.Int
	l  *big.Int
}

func NewVerifiableEncGroupEC(primes *qr.RSASpecialPrimes) (*VerifiableEncGroupEC, error) {
	rsaSpecial, err := qr.NewRSASpecialFromParams(primes)
	if err != nil {
		return nil, err
	}

	g1, err := rsaSpecial.GetRandomGenerator()
	if err != nil {
		return nil, err
	}

	h1, err := rsaSpecial.GetRandomGenerator()
	if err != nil {
		return nil, err
	}

	group := VerifiableEncGroupEC{
		RSASpecial: rsaSpecial,
		G1:         g1,
		H1:         h1,
	}
	return &group, nil
}
