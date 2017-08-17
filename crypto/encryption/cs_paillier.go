package encryption

import (
	"errors"
	"github.com/golang/protobuf/proto"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/dlog"
	pb "github.com/xlab-si/emmy/protobuf"
	"github.com/xlab-si/emmy/storage"
	"log"
	"math/big"
)

// todo: does hash really need to be into [0, 2^l]?

// http://eprint.iacr.org/2002/161.pdf
// Camenisch-Shoup variant of Paillier to make it (Paillier) CCA2 secure
type CSPaillier struct {
	SecParams *CSPaillierSecParams
	n1        *big.Int // n'
	PubKey    *CSPaillierPubKey
	SecretKey *CSPaillierSecretKey
	// verifierRandomData: encryptor stores s, r1, s1, m1;
	verifierRandomData *CSPaillierVerifierRandomData
	// proverRandomData stores c, u1, e1, v1, delta1, l1
	proverRandomData *CSPaillierProverRandomData
	proverEncData    *CSPaillierProverEncData
	verifierEncData  *CSPaillierVerifierEncData
}

type CSPaillierSecParams struct {
	L        int // length of p1 and q1 (l in a paper)
	RoLength int // ro is order of cyclic group Gamma (used for discrete logarithm)
	K        int // k in a paper; it must hold 2**K < min{p1, q1, ro}
	K1       int // k' in a paper; it must hold ro * 2**(K + K1 + 3) < n
	// lambda *big.Int // security parameters are function of lambda in a paper
}

type CSPaillierSecretKey struct {
	N  *big.Int
	G  *big.Int
	X1 *big.Int
	X2 *big.Int
	X3 *big.Int
	// the parameters below are for verifiable encryption
	Gamma                *dlog.ZpDLog // for discrete logarithm
	VerifiableEncGroupN  *big.Int
	VerifiableEncGroupG1 *big.Int
	VerifiableEncGroupH1 *big.Int
	K                    int
	K1                   int
}

// CSPaillierPubKey currently does not use auxilary parameters/primes - no additional n, p, q parameters
// (as specified in a paper, original n, p, q can be used).
type CSPaillierPubKey struct {
	N  *big.Int
	G  *big.Int
	Y1 *big.Int
	Y2 *big.Int
	Y3 *big.Int
	// the parameters below are for verifiable encryption
	Gamma                *dlog.ZpDLog // for discrete logarithm
	VerifiableEncGroupN  *big.Int
	VerifiableEncGroupG1 *big.Int
	VerifiableEncGroupH1 *big.Int
	K                    int
	K1                   int
}

type CSPaillierProverRandomData struct {
	S  *big.Int
	R1 *big.Int
	S1 *big.Int
	M1 *big.Int
}

type CSPaillierVerifierRandomData struct {
	L      *big.Int
	U1     *big.Int
	E1     *big.Int
	V1     *big.Int
	Delta1 *big.Int
	L1     *big.Int
	C      *big.Int
}

type CSPaillierProverEncData struct {
	R *big.Int
	M *big.Int
}

type CSPaillierVerifierEncData struct {
	U     *big.Int
	E     *big.Int
	V     *big.Int
	Label *big.Int
	Delta *big.Int
}

func NewCSPaillier(secParams *CSPaillierSecParams) *CSPaillier {
	var cspaillier CSPaillier

	cspaillier = CSPaillier{
		SecParams: secParams,
	}
	cspaillier.generateKey()

	return &cspaillier
}

func NewCSPaillierFromSecKey(path string) (*CSPaillier, error) {
	bytes, err := storage.Load(path)
	if err != nil {
		return nil, err
	}
	sKey := &pb.CSPaillierSecretKey{}
	err = proto.Unmarshal(bytes, sKey)
	if err != nil {
		return nil, err
	}

	gamma := dlog.ZpDLog{
		P:               new(big.Int).SetBytes(sKey.DLogP),
		G:               new(big.Int).SetBytes(sKey.DLogG),
		OrderOfSubgroup: new(big.Int).SetBytes(sKey.DLogQ),
	}
	secKey := CSPaillierSecretKey{
		N:                    new(big.Int).SetBytes(sKey.N),
		G:                    new(big.Int).SetBytes(sKey.G),
		X1:                   new(big.Int).SetBytes(sKey.X1),
		X2:                   new(big.Int).SetBytes(sKey.X2),
		X3:                   new(big.Int).SetBytes(sKey.X3),
		Gamma:                &gamma,
		VerifiableEncGroupN:  new(big.Int).SetBytes(sKey.VerifiableEncGroupN),
		VerifiableEncGroupG1: new(big.Int).SetBytes(sKey.VerifiableEncGroupG1),
		VerifiableEncGroupH1: new(big.Int).SetBytes(sKey.VerifiableEncGroupH1),
		K:                    int(sKey.K),
		K1:                   int(sKey.K1),
	}

	var cspaillier CSPaillier
	cspaillier = CSPaillier{
		SecretKey: &secKey,
	}

	pKey := &CSPaillierPubKey{
		N: secKey.N,
	}
	cspaillier.PubKey = pKey // Abs is used also in decrypt where PubKey is called

	return &cspaillier, nil
}

func NewCSPaillierFromPubKey(pubKey *CSPaillierPubKey) *CSPaillier {
	var cspaillier CSPaillier

	cspaillier = CSPaillier{
		PubKey: pubKey,
	}

	return &cspaillier
}

func NewCSPaillierFromPubKeyFile(path string) (*CSPaillier, error) {
	bytes, err := storage.Load(path)
	if err != nil {
		return nil, err
	}
	pKey := &pb.CSPaillierPubKey{}
	err = proto.Unmarshal(bytes, pKey)
	if err != nil {
		return nil, err
	}

	gamma := dlog.ZpDLog{
		P:               new(big.Int).SetBytes(pKey.DLogP),
		G:               new(big.Int).SetBytes(pKey.DLogG),
		OrderOfSubgroup: new(big.Int).SetBytes(pKey.DLogQ),
	}
	pubKey := CSPaillierPubKey{
		N:                    new(big.Int).SetBytes(pKey.N),
		G:                    new(big.Int).SetBytes(pKey.G),
		Y1:                   new(big.Int).SetBytes(pKey.Y1),
		Y2:                   new(big.Int).SetBytes(pKey.Y2),
		Y3:                   new(big.Int).SetBytes(pKey.Y3),
		Gamma:                &gamma,
		VerifiableEncGroupN:  new(big.Int).SetBytes(pKey.VerifiableEncGroupN),
		VerifiableEncGroupG1: new(big.Int).SetBytes(pKey.VerifiableEncGroupG1),
		VerifiableEncGroupH1: new(big.Int).SetBytes(pKey.VerifiableEncGroupH1),
		K:                    int(pKey.K),
		K1:                   int(pKey.K1),
	}

	var cspaillier CSPaillier

	cspaillier = CSPaillier{
		PubKey: &pubKey,
	}

	return &cspaillier, nil
}

func (cspaillier *CSPaillier) StoreSecKey(path string) error {
	secKey := &pb.CSPaillierSecretKey{
		N:                    cspaillier.SecretKey.N.Bytes(),
		G:                    cspaillier.SecretKey.G.Bytes(),
		X1:                   cspaillier.SecretKey.X1.Bytes(),
		X2:                   cspaillier.SecretKey.X2.Bytes(),
		X3:                   cspaillier.SecretKey.X3.Bytes(),
		DLogP:                cspaillier.SecretKey.Gamma.P.Bytes(),
		DLogG:                cspaillier.SecretKey.Gamma.G.Bytes(),
		DLogQ:                cspaillier.SecretKey.Gamma.OrderOfSubgroup.Bytes(),
		VerifiableEncGroupN:  cspaillier.SecretKey.VerifiableEncGroupN.Bytes(),
		VerifiableEncGroupG1: cspaillier.SecretKey.VerifiableEncGroupG1.Bytes(),
		VerifiableEncGroupH1: cspaillier.SecretKey.VerifiableEncGroupH1.Bytes(),
		K:                    int32(cspaillier.SecretKey.K),
		K1:                   int32(cspaillier.SecretKey.K1),
	}
	data, err := proto.Marshal(secKey)
	if err != nil {
		return err
	}
	err = storage.Store(data, path)
	if err != nil {
		return err
	}
	return nil
}

func (cspaillier *CSPaillier) StorePubKey(path string) error {
	pubKey := &pb.CSPaillierPubKey{
		N:                    cspaillier.PubKey.N.Bytes(),
		G:                    cspaillier.PubKey.G.Bytes(),
		Y1:                   cspaillier.PubKey.Y1.Bytes(),
		Y2:                   cspaillier.PubKey.Y2.Bytes(),
		Y3:                   cspaillier.PubKey.Y3.Bytes(),
		DLogP:                cspaillier.PubKey.Gamma.P.Bytes(),
		DLogG:                cspaillier.PubKey.Gamma.G.Bytes(),
		DLogQ:                cspaillier.PubKey.Gamma.OrderOfSubgroup.Bytes(),
		VerifiableEncGroupN:  cspaillier.PubKey.VerifiableEncGroupN.Bytes(),
		VerifiableEncGroupG1: cspaillier.PubKey.VerifiableEncGroupG1.Bytes(),
		VerifiableEncGroupH1: cspaillier.PubKey.VerifiableEncGroupH1.Bytes(),
		K:                    int32(cspaillier.PubKey.K),
		K1:                   int32(cspaillier.PubKey.K1),
	}
	data, err := proto.Marshal(pubKey)
	if err != nil {
		return err
	}
	err = storage.Store(data, path)
	if err != nil {
		return err
	}
	return nil
}

// Returns (u, e, v).
func (cspaillier *CSPaillier) Encrypt(m, label *big.Int) (*big.Int, *big.Int, *big.Int, error) {
	if m.Cmp(cspaillier.PubKey.N) >= 0 {
		err := errors.New("msg is too big")
		return nil, nil, nil, err
	}

	b := new(big.Int).Div(cspaillier.PubKey.N, big.NewInt(4))
	r := common.GetRandomInt(b)

	n2 := new(big.Int).Mul(cspaillier.PubKey.N, cspaillier.PubKey.N)
	// u = g^r
	u := new(big.Int).Exp(cspaillier.PubKey.G, r, n2)

	// e = y1^r * h^m
	e1 := new(big.Int).Exp(cspaillier.PubKey.Y1, r, n2)       // y1^r
	h := new(big.Int).Add(cspaillier.PubKey.N, big.NewInt(1)) // 1 + n
	e2 := new(big.Int).Exp(h, m, n2)                          // h^m

	e := new(big.Int).Mul(e1, e2) // y1^r * h^m
	e.Mod(e, n2)

	// v = abs((y2 * y3^hash(u, e, L))^r)
	hashNum := common.Hash(u, e, label)

	t := new(big.Int).Exp(cspaillier.PubKey.Y3, hashNum, n2) // y3^hashNum
	t.Mul(cspaillier.PubKey.Y2, t)                           // y2 * y3^hashNum
	t.Exp(t, r, n2)                                          // (y2 * y3^hashNum)^r

	v, _ := cspaillier.Abs(t)

	cspaillier.proverEncData = &CSPaillierProverEncData{
		R: r,
		M: m,
	}

	return u, e, v, nil
}

func (cspaillier *CSPaillier) Decrypt(u, e, v, label *big.Int) (*big.Int, error) {
	// check whether Abs(v) = v:
	vAbs, _ := cspaillier.Abs(v)
	if v.Cmp(vAbs) != 0 {
		err := errors.New("v != abs(v)")
		return nil, err
	}

	// check whether u^(2 * (x2 + hash(u, e, L) * x3)) = v^2:
	// hash(u, e, L)
	hashNum := common.Hash(u, e, label)

	// hash(u, e, L) * x3
	t := new(big.Int).Mul(hashNum, cspaillier.SecretKey.X3)

	// x2 + hash(u, e, L) * x3:
	t.Add(cspaillier.SecretKey.X2, t)
	t.Mul(t, big.NewInt(2))

	n2 := new(big.Int).Mul(cspaillier.PubKey.N, cspaillier.PubKey.N)
	t.Exp(u, t, n2)
	t.Mod(t, n2)

	v2 := new(big.Int).Mul(v, v)
	v2.Mod(v2, n2)

	if t.Cmp(v2) != 0 {
		err := errors.New("CSPaillier decryption failed 1")
		return nil, err
	}

	// check whether m1 is of the form h^m for some m from Z_n (meaning m1 = 1 + m * n)
	ux1 := new(big.Int).Exp(u, cspaillier.SecretKey.X1, n2) // u^x1
	ux1Inv := new(big.Int).ModInverse(ux1, n2)              // u^x1_inv

	m1 := new(big.Int).Mul(e, ux1Inv)
	m1.Mod(m1, n2)

	m1min := new(big.Int).Sub(m1, big.NewInt(1))
	m1minModulo := new(big.Int).Mod(m1min, cspaillier.PubKey.N)

	if m1minModulo.Cmp(big.NewInt(0)) != 0 {
		err := errors.New("CSPaillier decryption failed 2")
		return nil, err
	}

	m := new(big.Int).Div(m1min, cspaillier.PubKey.N)

	return m, nil
}

func (cspaillier *CSPaillier) Abs(a *big.Int) (*big.Int, error) {
	n2 := new(big.Int).Mul(cspaillier.PubKey.N, cspaillier.PubKey.N)
	if a.Cmp(n2) >= 0 {
		err := errors.New("value is too big for abs function")
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

func (cspaillier *CSPaillier) generateKey() {
	p1 := common.GetGermainPrime(cspaillier.SecParams.L)
	q1 := common.GetGermainPrime(cspaillier.SecParams.L)

	p := new(big.Int).Add(p1, p1)
	p.Add(p, big.NewInt(1))

	q := new(big.Int).Add(q1, q1)
	q.Add(q, big.NewInt(1))

	//cspaillier.lambda = common.LCM(p_min, q_min)
	n := new(big.Int).Mul(p, q)
	cspaillier.n1 = new(big.Int).Mul(p1, q1)
	n2 := new(big.Int).Mul(n, n)

	pubKey := CSPaillierPubKey{
		N: n,
	}

	// for verifiable encryption:
	Gamma, err := dlog.NewZpSchnorr(cspaillier.SecParams.RoLength)
	if err != nil {
		log.Fatal(err)
	}
	pubKey.Gamma = Gamma

	// it must hold:
	// 2**K < min{p1, q1, ro}; ro is Gamma.OrderOfSubgroup
	// ro * 2**(K + K1 + 3) < n

	check1 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cspaillier.SecParams.K)), nil)
	if check1.Cmp(p1) >= 0 || check1.Cmp(q1) >= 0 || check1.Cmp(Gamma.OrderOfSubgroup) >= 0 {
		log.Fatal(err)
	}

	tmp := cspaillier.SecParams.K + cspaillier.SecParams.K1 + 3
	check2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(tmp)), nil)
	check2.Mul(check2, Gamma.OrderOfSubgroup)

	if check2.Cmp(n) >= 0 {
		log.Fatal(err)
	}

	pubKey.K = cspaillier.SecParams.K
	pubKey.K1 = cspaillier.SecParams.K1

	// Now we need to compute two generators in Z_n* subgroup of order n1.
	// Note that here a different n might be used from the one in encryption,
	// however as above we assume the same (the paper says it can be the same).
	orderOfZn := new(big.Int).Mul(big.NewInt(4), cspaillier.n1)
	verifiableEncGroup, err := NewVerifiableEncGroup(n, orderOfZn, cspaillier.n1)
	if err != nil {
		log.Fatal(err)
	}

	pubKey.VerifiableEncGroupN = verifiableEncGroup.N
	pubKey.VerifiableEncGroupG1 = verifiableEncGroup.G1
	pubKey.VerifiableEncGroupH1 = verifiableEncGroup.H1

	secretKey := CSPaillierSecretKey{
		N:  n,
		K:  cspaillier.SecParams.K,
		K1: cspaillier.SecParams.K1,
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
	cspaillier.PubKey = &pubKey
	cspaillier.SecretKey = &secretKey
}

// Returns l = g1^m * h1^s where s is a random integer smaller than n/4.
func (cspaillier *CSPaillier) GetOpeningMsg(m *big.Int) (*big.Int, *big.Int) {
	b := new(big.Int).Div(cspaillier.PubKey.VerifiableEncGroupN, big.NewInt(4))
	s := common.GetRandomInt(b)

	t1 := new(big.Int).Exp(cspaillier.PubKey.VerifiableEncGroupG1, m,
		cspaillier.PubKey.VerifiableEncGroupN)
	t2 := new(big.Int).Exp(cspaillier.PubKey.VerifiableEncGroupH1, s,
		cspaillier.PubKey.VerifiableEncGroupN)
	l := new(big.Int).Mul(t1, t2)
	l.Mod(l, cspaillier.PubKey.VerifiableEncGroupN)

	cspaillier.proverRandomData = &CSPaillierProverRandomData{
		S: s,
	}

	delta := new(big.Int).Exp(cspaillier.PubKey.Gamma.G, m, cspaillier.PubKey.Gamma.P)
	return l, delta
}

// Prover (encryptor) should use this function to generate values for the first sigma protocol message.
func (cspaillier *CSPaillier) GetProofRandomData(u, e, label *big.Int) (*big.Int, *big.Int,
	*big.Int, *big.Int, *big.Int, error) {
	two := big.NewInt(2)
	t1 := new(big.Int).Exp(two, big.NewInt(int64(cspaillier.PubKey.K+cspaillier.PubKey.K1-2)), nil)
	b1 := new(big.Int).Mul(cspaillier.PubKey.N, t1)
	r1, err := common.GetRandomIntFromRange(new(big.Int).Neg(b1), b1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	b2 := new(big.Int).Mul(cspaillier.PubKey.VerifiableEncGroupN, t1)
	s1, err := common.GetRandomIntFromRange(new(big.Int).Neg(b2), b2)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	t2 := new(big.Int).Exp(two, big.NewInt(int64(cspaillier.PubKey.K+cspaillier.PubKey.K1)), nil)
	b3 := new(big.Int).Mul(cspaillier.PubKey.Gamma.OrderOfSubgroup, t2)
	m1, err := common.GetRandomIntFromRange(new(big.Int).Neg(b3), b3)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	n2 := new(big.Int).Mul(cspaillier.PubKey.N, cspaillier.PubKey.N)

	// u1 = g^(2*r1)
	u1 := common.Exponentiate(cspaillier.PubKey.G, new(big.Int).Mul(big.NewInt(2), r1), n2)

	// e1 = y1^(2*r1) * h^(2*m1)
	h := new(big.Int).Add(cspaillier.PubKey.N, big.NewInt(1)) // 1 + n
	e1Part1 := common.Exponentiate(cspaillier.PubKey.Y1, new(big.Int).Mul(big.NewInt(2), r1), n2)
	e1Part2 := common.Exponentiate(h, new(big.Int).Mul(big.NewInt(2), m1), n2)
	e1 := new(big.Int).Mul(e1Part1, e1Part2)
	e1.Mod(e1, n2)

	// v1 = (y2 * y3^hash(u, e, L))^(2*r1)
	hashNum := common.Hash(u, e, label)
	v11 := new(big.Int).Exp(cspaillier.PubKey.Y3, hashNum, n2)
	v11.Mul(v11, cspaillier.PubKey.Y2)
	v11.Mod(v11, n2)
	v1 := common.Exponentiate(v11, new(big.Int).Mul(big.NewInt(2), r1), n2)

	// delta1 = gamma^m1
	delta1 := common.Exponentiate(cspaillier.PubKey.Gamma.G, m1,
		cspaillier.PubKey.Gamma.P)

	// l1 = g1^m1 * h1^s1
	l11 := common.Exponentiate(cspaillier.PubKey.VerifiableEncGroupG1, m1,
		cspaillier.PubKey.VerifiableEncGroupN)
	l12 := common.Exponentiate(cspaillier.PubKey.VerifiableEncGroupH1, s1,
		cspaillier.PubKey.VerifiableEncGroupN)
	l1 := new(big.Int).Mul(l11, l12)
	l1.Mod(l1, cspaillier.PubKey.VerifiableEncGroupN)

	cspaillier.proverRandomData.R1 = r1
	cspaillier.proverRandomData.S1 = s1
	cspaillier.proverRandomData.M1 = m1
	return u1, e1, v1, delta1, l1, nil
}

// Prover should use this function to compute data for second (last) sigma protocol message.
func (cspaillier *CSPaillier) GetProofData(c *big.Int) (*big.Int, *big.Int, *big.Int) {
	// rTilde = r1 - c * r
	t := new(big.Int).Mul(c, cspaillier.proverEncData.R)
	rTilde := new(big.Int).Sub(cspaillier.proverRandomData.R1, t)

	// sTilde = s1 - c * s
	t.Mul(c, cspaillier.proverRandomData.S)
	sTilde := new(big.Int).Sub(cspaillier.proverRandomData.S1, t)

	// mTilde = m1 - c * m
	t.Mul(c, cspaillier.proverEncData.M)
	mTilde := new(big.Int).Sub(cspaillier.proverRandomData.M1, t)
	return rTilde, sTilde, mTilde
}

// Verifier should call this function when it receives l = g1^m * h1^s as the first protocol message.
func (cspaillier *CSPaillier) SetVerifierEncData(u, e, v, delta, label, l *big.Int) {
	cspaillier.verifierRandomData = &CSPaillierVerifierRandomData{
		L: l,
	}
	cspaillier.verifierEncData = &CSPaillierVerifierEncData{
		U:     u,
		E:     e,
		V:     v,
		Label: label,
		Delta: delta,
	}
}

func (cspaillier *CSPaillier) Verify(rTilde, sTilde, mTilde *big.Int) bool {
	// u1 = cspaillier.verifierRandomData.U1
	// u = cspaillier.verifierEncData.U
	// c = cspaillier.verifierRandomData.C
	// g = cspaillier.PubKey.G

	// check if u1 = u^(2*c) * g^(2*rTilde)
	n2 := new(big.Int).Mul(cspaillier.PubKey.N, cspaillier.PubKey.N)
	twoC := new(big.Int).Mul(cspaillier.verifierRandomData.C, big.NewInt(2))
	twoRTilde := new(big.Int).Mul(rTilde, big.NewInt(2))

	t1 := common.Exponentiate(cspaillier.verifierEncData.U, twoC, n2)
	t2 := common.Exponentiate(cspaillier.SecretKey.G, twoRTilde, n2)
	t := new(big.Int).Mul(t1, t2)
	t.Mod(t, n2)
	if cspaillier.verifierRandomData.U1.Cmp(t) != 0 {
		log.Println("NOT OK 1")
		return false
	}

	// check if e1 = e^(2*c) * y1^(2*rTilde) * h^(2*mTilde)
	t1 = common.Exponentiate(cspaillier.verifierEncData.E, twoC, n2)
	y1 := common.Exponentiate(cspaillier.SecretKey.G, cspaillier.SecretKey.X1, n2)
	t2 = common.Exponentiate(y1, twoRTilde, n2)
	h := new(big.Int).Add(cspaillier.PubKey.N, big.NewInt(1)) // 1 + n
	t3 := common.Exponentiate(h, new(big.Int).Mul(big.NewInt(2), mTilde), n2)
	t.Mul(t1, t2)
	t.Mul(t, t3)
	t.Mod(t, n2)
	if cspaillier.verifierRandomData.E1.Cmp(t) != 0 {
		log.Println("NOT OK 2")
		return false
	}

	// check if v1 = v^(2*c) * (y2 * y3^hash(u, e, L))^(2*rTilde)
	t1 = common.Exponentiate(cspaillier.verifierEncData.V, twoC, n2)
	hashNum := common.Hash(cspaillier.verifierEncData.U, cspaillier.verifierEncData.E,
		cspaillier.verifierEncData.Label)
	y3 := common.Exponentiate(cspaillier.SecretKey.G, cspaillier.SecretKey.X3, n2)
	t21 := new(big.Int).Exp(y3, hashNum, n2)
	y2 := common.Exponentiate(cspaillier.SecretKey.G, cspaillier.SecretKey.X2, n2)
	t21.Mul(y2, t21)
	t2 = common.Exponentiate(t21, twoRTilde, n2)
	t.Mul(t1, t2)
	t.Mod(t, n2)
	if cspaillier.verifierRandomData.V1.Cmp(t) != 0 {
		log.Println("NOT OK 3")
		return false
	}

	// check if delta1 = delta^c * Gamma.G^mTilde
	t1.Exp(cspaillier.verifierEncData.Delta, cspaillier.verifierRandomData.C,
		cspaillier.SecretKey.Gamma.P)
	t2 = common.Exponentiate(cspaillier.SecretKey.Gamma.G, mTilde, cspaillier.SecretKey.Gamma.P)
	t.Mul(t1, t2)
	t.Mod(t, cspaillier.SecretKey.Gamma.P)
	if cspaillier.verifierRandomData.Delta1.Cmp(t) != 0 {
		log.Println("NOT OK 4")
		return false
	}

	// check if l1 = l^c * g1^mTilde * h1^sTilde
	t1.Exp(cspaillier.verifierRandomData.L, cspaillier.verifierRandomData.C, n2)
	t2 = common.Exponentiate(cspaillier.SecretKey.VerifiableEncGroupG1,
		mTilde, cspaillier.SecretKey.VerifiableEncGroupN)
	t3 = common.Exponentiate(cspaillier.SecretKey.VerifiableEncGroupH1,
		sTilde, cspaillier.SecretKey.VerifiableEncGroupN)
	t.Mul(t1, t2)
	t.Mul(t, t3)
	t.Mod(t, cspaillier.SecretKey.VerifiableEncGroupN)
	if cspaillier.verifierRandomData.L1.Cmp(t) != 0 {
		log.Println("NOT OK 5")
		return false
	}

	// check if -n/4 < mTilde < n/4
	b := new(big.Int).Div(cspaillier.PubKey.N, big.NewInt(4))
	if new(big.Int).Abs(mTilde).Cmp(b) >= 0 {
		log.Println("NOT OK 6")
		return false
	}

	return true
}

func (cspaillier *CSPaillier) GetChallenge() *big.Int {
	b := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(cspaillier.SecretKey.K)), nil)
	c := common.GetRandomInt(b)
	return c
}

// Verifier should call this function when it receives proof random data as the second protocol message.
func (cspaillier *CSPaillier) SetProofRandomData(u1, e1, v1, delta1, l1, c *big.Int) {
	cspaillier.verifierRandomData.U1 = u1
	cspaillier.verifierRandomData.E1 = e1
	cspaillier.verifierRandomData.V1 = v1
	cspaillier.verifierRandomData.Delta1 = delta1
	cspaillier.verifierRandomData.L1 = l1
	cspaillier.verifierRandomData.C = c
}

type VerifiableEncGroup struct {
	N  *big.Int
	N1 *big.Int
	G1 *big.Int
	H1 *big.Int
	l  *big.Int
}

func NewVerifiableEncGroup(n, orderOfZn, n1 *big.Int) (*VerifiableEncGroup, error) {
	g1, err := common.GetGeneratorOfZnSubgroup(n, orderOfZn, n1)
	h1, err := common.GetGeneratorOfZnSubgroup(n, orderOfZn, n1)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	group := VerifiableEncGroup{
		N:  n,
		N1: n1,
		G1: g1,
		H1: h1,
	}
	return &group, nil
}
