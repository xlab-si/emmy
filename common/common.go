package common

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"log"
	"math/big"
)

// It takes big.Int numbers, transform them to bytes, and concatenate the bytes.
func ConcatenateNumbers(numbers ...*big.Int) []byte {
	var bs []byte
	for _, n := range numbers {
		bs = append(bs, n.Bytes()...)
	}
	return bs
}

// It concatenates numbers (their bytes), computes a hash and outputs a hash as []byte.
func HashIntoBytes(numbers ...*big.Int) []byte {
	toBeHashed := ConcatenateNumbers(numbers...)
	sha512 := sha512.New()
	sha512.Write(toBeHashed)
	hashBytes := sha512.Sum(nil)
	return hashBytes
}

// It concatenates numbers (their bytes), computes a hash and outputs a hash as *big.Int.
func Hash(numbers ...*big.Int) *big.Int {
	hashBytes := HashIntoBytes(numbers...)
	hashNum := new(big.Int).SetBytes(hashBytes)
	return hashNum
}

// It computes x^y mod m. Negative y are supported.
func Exponentiate(x, y, m *big.Int) *big.Int {
	var r *big.Int
	if y.Cmp(big.NewInt(0)) >= 0 {
		r = new(big.Int).Exp(x, y, m)
	} else {
		r = new(big.Int).Exp(x, new(big.Int).Abs(y), m)
		r.ModInverse(r, m)
	}
	return r
}

// Computes least common multiple.
func LCM(x, y *big.Int) *big.Int {
	n := new(big.Int)
	n.Mul(x, y)
	d := new(big.Int)
	d.GCD(nil, nil, x, y)
	t := new(big.Int)
	t.Div(n, d)
	return t
}

// Returns random integer from [0, max).
func GetRandomInt(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		log.Fatal(err)
	}
	return n
}

// Returns random integer from [min, max).
func GetRandomIntFromRange(min, max *big.Int) (*big.Int, error) {
	if min.Cmp(max) >= 0 {
		err := errors.New("GetRandomIntFromRange: max has to be bigger than min")
		return nil, err
	}
	if min.Cmp(big.NewInt(0)) < 0 && max.Cmp(big.NewInt(0)) < 0 {
		d := new(big.Int).Sub(min, max)
		dAbs := new(big.Int).Abs(d)
		i := GetRandomInt(dAbs)
		ic := new(big.Int).Add(min, i)
		return ic, nil
	} else if min.Cmp(big.NewInt(0)) < 0 && max.Cmp(big.NewInt(0)) >= 0 {
		nMin := new(big.Int).Abs(min)
		d := new(big.Int).Add(nMin, max)
		i := GetRandomInt(d)
		ic := new(big.Int).Add(min, i)
		return ic, nil
	} else {
		d := new(big.Int).Sub(max, min)
		i := GetRandomInt(d)
		ic := new(big.Int).Add(min, i)
		return ic, nil
	}
}

// GetRandomIntOfLength returns random *big.Int exactly of length bitLengh.
func GetRandomIntOfLength(bitLength int) *big.Int {
	// choose a random number a of length bitLength
	// that means: 2^(bitLength-1) < a < 2^(bitLength)
	// choose a random from [0, 2^(bitLength-1)) and add it to 2^(bitLength-1)
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLength-1)), nil)
	o := GetRandomInt(max)
	r := new(big.Int).Add(max, o)

	b1 := r.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLength-1)), nil))
	b2 := r.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLength)), nil))
	if (b1 != 1) || (b2 != -1) {
		log.Panic("parameter not properly chosen")
	}

	return r
}

// IsQuadraticResidue returns true if a is quadratic residue in Z_n and false otherwise.
// It works only when p is prime.
func IsQuadraticResidue(a *big.Int, p *big.Int) (bool, error) {
	if !p.ProbablyPrime(20) {
		err := errors.New("p is not prime")
		return false, err
	}

	// check whether a^((p-1)/2) is 1 or -1 (Euler's criterion)
	p1 := new(big.Int).Sub(p, big.NewInt(1))
	p1 = new(big.Int).Div(p1, big.NewInt(2))
	cr := new(big.Int).Exp(a, p1, p)

	if cr.Cmp(big.NewInt(1)) == 0 {
		return true, nil
	} else if cr.Cmp(new(big.Int).Sub(p, big.NewInt(1))) == 0 {
		return false, nil
	} else {
		err := errors.New("seems that p is not prime")
		return false, err
	}
}

// GetGeneratorOfZnSubgroup returns a generator of a subgroup of a specified order in Z_n.
// Parameter groupOrder is order of Z_n (if n is prime, order is n-1).
func GetGeneratorOfZnSubgroup(n, groupOrder, subgroupOrder *big.Int) (*big.Int, error) {
	if big.NewInt(0).Mod(groupOrder, subgroupOrder).Cmp(big.NewInt(0)) != 0 {
		err := errors.New("subgroupOrder does not divide groupOrder")
		return nil, err
	}
	r := new(big.Int).Div(groupOrder, subgroupOrder)
	for {
		h := GetRandomInt(n)
		g := new(big.Int)
		g.Exp(h, r, n)
		if g.Cmp(big.NewInt(1)) != 0 {
			return g, nil
		}
	}
}

// GetGeneratorOfCompositeQR returns a generator of a group of quadratic residues.
// The parameters p and q need to be safe primes.
func GetGeneratorOfCompositeQR(p, q *big.Int) (g *big.Int, err error) {
	n := new(big.Int).Mul(p, q)
	one := big.NewInt(1)
	two := big.NewInt(2)
	tmp := new(big.Int)

	// check if p and q are safe primes:
	p1 := new(big.Int)
	p1.Sub(p, one)
	p1.Div(p1, two)
	q1 := new(big.Int)
	q1.Sub(q, one)
	q1.Div(q1, two)

	if p.ProbablyPrime(20) && q.ProbablyPrime(20) && p1.ProbablyPrime(20) && q1.ProbablyPrime(20) {
	} else {
		err := errors.New("p and q need to be safe primes")
		return nil, err
	}

	// The possible orders are 2, p1, q1, 2 * p1, 2 * q1, and 2 * p1 * q1.
	// We need to make sure that all elements of orders smaller than 2 * p1 * q1 are ruled out.

	for {
		a := GetRandomInt(n)
		a_plus := new(big.Int).Add(a, one)
		a_min := new(big.Int).Sub(a, one)
		tmp.GCD(nil, nil, a, p)
		// p
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_plus, p)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_min, p)
		if tmp.Cmp(one) != 0 {
			continue
		}

		// q
		tmp.GCD(nil, nil, a, q)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_plus, q)
		if tmp.Cmp(one) != 0 {
			continue
		}
		tmp.GCD(nil, nil, a_min, q)
		if tmp.Cmp(one) != 0 {
			continue
		}

		g := a.Mul(a, big.NewInt(2))
		return g, nil
	}
}

// It returns primes p and q where p = r * q + 1 for some integer r.
func GetSchnorrGroup(qBitLength int) (*big.Int, *big.Int, *big.Int, error) {
	// Using DSA GenerateParameters:

	sizes := dsa.L1024N160

	if qBitLength == 160 {
		sizes = dsa.L1024N160
	} else if qBitLength == 224 {
		sizes = dsa.L2048N224
	} else if qBitLength == 256 {
		sizes = dsa.L2048N256
		//} else if qBitLength == 256 {
		//	sizes = dsa.L3072N256
	} else {
		err := errors.New("generating Schnorr primes for these bitlengths is not supported")
		return nil, nil, nil, err
	}

	params := dsa.Parameters{}
	err := dsa.GenerateParameters(&params, rand.Reader, sizes)
	log.Println(err)
	if err == nil {
		return params.G, params.Q, params.P, nil
	} else {
		return nil, nil, nil, err
	}
}

// GetSafePrime returns a safe prime p (p = 2*p1 + 2 where p1 is prime too).
func GetSafePrime(bits int) (p *big.Int, err error) {
	p1 := GetGermainPrime(bits - 1)
	p = big.NewInt(0)
	p.Mul(p1, big.NewInt(2))
	p.Add(p, big.NewInt(1))

	if p.BitLen() == bits {
		return p, nil
	} else {
		err := errors.New("bit length not correct")
		return nil, err
	}
}

// GetGermainPrime returns a prime number p for which 2*p + 1 is also prime. Note that conversely p
// is called safe prime.
func GetGermainPrime(bits int) (p *big.Int) {
	// multiple germainPrime goroutines are called and we assume at least one will compute a
	// safe prime and send it to the channel, thus we do not handle errors in germainPrime
	var c chan *big.Int = make(chan *big.Int)
	var quit chan int = make(chan int)
	for j := int(0); j < 8; j++ {
		go germainPrime(bits, c, quit)
	}
	msg := <-c
	close(c)
	close(quit)
	return msg
}

var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big.Int
// operations.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// germainPrime is slightly modified Prime function from:
// https://github.com/golang/go/blob/master/src/crypto/rand/util.go
// germainPrime returns a number, p, of the given size, such that p and 2*p+1 are primes
// with high probability.
// germainPrime will return error for any error returned by rand.Read or if bits < 2.
func germainPrime(bits int, c chan *big.Int, quit chan int) (p *big.Int, err error) {
	rand := rand.Reader

	if bits < 2 {
		err = errors.New("crypto/rand: prime size must be at least 2-bit")
		return
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p = new(big.Int)
	p1 := new(big.Int)

	bigMod := new(big.Int)

	for {
		select {
		case <-quit:
			return
		default:
			// this is to make it non-blocking
		}

		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)
		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)

		// Calculate the value mod the product of smallPrimes. If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(p, smallPrimesProduct)
		mod := bigMod.Uint64()

	NextDelta:
		for delta := uint64(0); delta < 1<<20; delta += 2 {
			m := mod + delta
			for _, prime := range smallPrimes {
				if m%uint64(prime) == 0 && (bits > 6 || m != uint64(prime)) {
					continue NextDelta
				}

				// 2*mod + 2*delta + 1	should not be divisible by smallPrimes as well
				m1 := (2*m + 1) % smallPrimesProduct.Uint64()

				if m1%uint64(prime) == 0 && (bits > 6 || m1 != uint64(prime)) {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta)
				p.Add(p, bigMod)
			}

			p1.Add(p, p)
			p1.Add(p1, big.NewInt(1))
			break
		}

		// There is a tiny possibility that, by adding delta, we caused
		// the number to be one bit too long. Thus we check BitLen
		// here.
		if p.ProbablyPrime(20) && p.BitLen() == bits {
			if p1.ProbablyPrime(20) {
				// waiting for a message about channel being closed is repeated here,
				// because it might happen that channel is closed after waiting at the
				// beginning of for loop above (but we want to have it there also,
				// otherwise it this goroutine might be searching for a germain
				// prime for some time after one was found by another goroutine
				select {
				case <-quit:
					return
				default:
					// this is to make it non-blocking
				}

				c <- p
				return
			}
		}
	}
}
