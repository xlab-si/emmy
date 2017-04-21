package common

import (
	"math/big"
	"crypto/rand"
	"log"
)

func BackToBytes(in []uint64, howMany int) []byte {
	bys := make([]byte, 128)
	for i := int(0); i < len(in); i++ {
		// in[i] for example < 2^64
		for j := int(0); j < howMany; j++ {
			b := in[i] >> uint((howMany - j - 1) * howMany)
			//log.Println(b)
			//log.Println("-----")
			bys[i*howMany + j] = byte(b & 255)
			//bys[i*howMany + j] = byte((in[i] >> uint(howMany - j - 1)))
		}
	}
	return bys
}

func MergeBytes(n *big.Int, howMany int) []uint64 {
	bys := n.Bytes()
	ln := len(bys)
		
	mergeBytes := 8
	aLen := ln/mergeBytes
	if ln > aLen * mergeBytes {
		aLen++
	}
	//myEl := make([]*big.Int, aLen)
	myEl := make([]uint64, aLen)
	
	for i := int(0); i < ln; i=i+mergeBytes {
		var s uint64
		
		for j := int(0); j < mergeBytes; j++ {
			if i+j == ln {
				break
			}
			//b := big.NewInt(int64(bys[ln-(i+j)-1]))
			b := bys[ln-(i+j)-1]
			//f := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(8*j)), nil)
			//f := math.Pow(float64(2), float64(8*j))
			//f := 1 << uint(8*j) // 2^(8*j)
			
			//b.Mul(b, f)
			//s.Add(s, b)
			//s += uint64(b) * uint64(f)
			//s += uint64(b) << uint(8*j)
			s |= uint64(b) << uint(8*j)
		}
		
		//log.Println(aLen-1-i/mergeBytes)
		myEl[aLen - 1 - i/mergeBytes] = s
		//myEl[i/mergeBytes] = s
	}
	return myEl
}

func GetStrongPrime(bitLength int) *big.Int {
	two := big.NewInt(2)
	one := big.NewInt(1)
	n, _ := rand.Prime(rand.Reader, bitLength)
	m1 := new(big.Int)
	m1.Mod(n, two)
	if m1.Cmp(big.NewInt(0)) == 0 {
		n.Add(n, one)
	}
	
	ind := 0
	for {
		ind += 1
		if (ind % 1000 == 0) {
			log.Println(ind)
		}
		n.Add(n, two)
		isCand := true

		if isCand {
			if n.ProbablyPrime(20) {
				log.Println("+++++")
				return n
			}
		}
		
		//n1 := new(big.Int).Mul(n, two)
		//n2 := new(big.Int).Add(n1, one)
		//n.Lsh(n, 2)
		//n.Add(n, one)
		
		//log.Println(len(n.Bytes()))
		//log.Println(n.Bytes())
		
		//myEl := MergeBytes(n, 8)		
		//bys := BackToBytes(myEl, 8)
		//BackToBytes(myEl, 8)
		//log.Println(bys)
		//log.Println(n.Bytes())
		//log.Println("+++++++++++++++++++++")
		
		
		/*
		bys = n.Bytes()
		
		for i := uint(0); i < aLen; i++ {
			var[aLen - i - 1] = bys[aLen - 4*(i+1)] * (4*(i+1) - 1)
		}
		*/
		
		//tra := new(big.Int).SetBytes(bla)
		//log.Println(tra)
		//log.Println(n1)
		//log.Println("-------------")
		//n1 = new(big.Int).Add(n1, big.NewInt(1))
				
		/*
		stillCandidate := true
		for _, el := range Sieve {
			z := new(big.Int).Mod(n1, big.NewInt(int64(el)))
			if z.Cmp(big.NewInt(0)) == 0 {
				stillCandidate = false
				break
			}
		}
		
		if stillCandidate {
			log.Println("+++++++++++++++")
			if n1.ProbablyPrime(10) {
				return n
			}
		}
		log.Println("-------------")
		*/
		//isPrime := n1.ProbablyPrime(5)
		//log.Println(isPrime)
	}
	log.Println("-----------------------------")
	return nil
}
