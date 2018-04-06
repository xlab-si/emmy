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

import (
	"fmt"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"math/big"
)

type CLPubKey struct {
	N   *big.Int
	S   *big.Int
	Z   *big.Int
	R_L []*big.Int
}

func NewCLPubKey(N *big.Int, S, Z *big.Int, R_L []*big.Int) *CLPubKey {
	return &CLPubKey{
		N:   N,
		S:   S,
		Z:   Z,
		R_L: R_L,
	}
}

type CLOrg struct {
	group *groups.QRSpecialRSA
	PubKey *CLPubKey
	x_Z *big.Int // Z = S^x_Z
	x_R []*big.Int // R_i = S^x_R_i
}

func NewOrg(clParamSizes *CLParamSizes) (*CLOrg, error) {
	group, err := groups.NewQRSpecialRSA(clParamSizes.L_n / 2)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	S, Z, R_L, x_Z, x_R, err := generateQuadraticResidues(group, clParamSizes.L_attrs)
	pubKey := NewCLPubKey(group.N, S, Z, R_L)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	primes := common.NewSpecialRSAPrimes(group.P, group.Q, group.P1, group.Q1)
	return NewOrgFromExistingParams(primes, pubKey, x_Z, x_R)
}

func NewOrgFromExistingParams(primes *common.SpecialRSAPrimes, pubKey *CLPubKey, x_Z *big.Int,
		x_R []*big.Int) (*CLOrg, error) {
	group, err := groups.NewQRSpecialRSAFromExistingParams(primes)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	return &CLOrg{
		group: group,
		PubKey: pubKey,
		x_Z: x_Z,
		x_R: x_R,
	}, nil
}

func generateQuadraticResidues(group *groups.QRSpecialRSA, num_of_attrs int) (*big.Int, *big.Int, []*big.Int,
		*big.Int, []*big.Int, error) {
	S, err := group.GetRandomGenerator()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error when searching for QRSpecialRSA generator: %s", err)
	}
	x_Z := common.GetRandomInt(group.Order)
	Z := group.Exp(S, x_Z)

	R_L := make([]*big.Int, num_of_attrs)
	x_R := make([]*big.Int, num_of_attrs)
	for i, _ := range R_L {
		x_R_i := common.GetRandomInt(group.Order)
		x_R[i] = x_R_i
		R_i := group.Exp(S, x_R_i)
		R_L[i] = R_i
	}
	return S, Z, R_L, x_Z, x_R, nil
}