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

package common

import (
	"crypto/rand"
	"errors"
	"log"
	"math/big"
)

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
