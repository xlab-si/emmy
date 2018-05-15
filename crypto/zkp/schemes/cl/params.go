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

package cl

import ()

type CLParamSizes struct {
	// There are only a few possibilities for RhoBitLen. 256 implies that the modulus
	// bit length is 2048
	RhoBitLen  int // bit length of order of the commitment group
	NLength    int // bit length of RSA modulus
	AttrsNum   int // number of attributes
	AttrBitLen int // bit length of attribute
	HashBitLen int // bit length of hash output used for Fiat-Shamir
	SecParam   int // security parameter
	EBitLen    int // size of e values of certificates
	E1BitLen   int // size of the interval the e values are taken from
	VBitLen    int // size of the v values of the certificates
}

// TODO: add method to load params from file or blockchain or wherever they will be stored.
func GetDefaultParamSizes() *CLParamSizes {
	return &CLParamSizes{
		RhoBitLen:  256,
		NLength:    1024,
		AttrsNum:   3,
		AttrBitLen: 256,
		HashBitLen: 512,
		SecParam:   80,
		EBitLen:    597,
		E1BitLen:   120,
		VBitLen:    2724,
	}
}
