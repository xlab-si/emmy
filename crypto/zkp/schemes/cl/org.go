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
	"math/big"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

type PubKey struct {
	N           *big.Int
	S           *big.Int
	Z           *big.Int
	RsKnown     []*big.Int // one R corresponds to one attribute - these attributes are known to both - receiver and issuer
	RsCommitted []*big.Int // issuer knows only commitments of these attributes
	RsHidden    []*big.Int // only receiver knows these attributes
	// the fields below are for commitments of the (committed) attributes
	N1 *big.Int
	G  *big.Int
	H  *big.Int
}

func NewPubKey(N *big.Int, S, Z *big.Int, RsKnown, RsCommitted, RsHidden []*big.Int, N1, G, H *big.Int) *PubKey {
	return &PubKey{
		N:           N,
		S:           S,
		Z:           Z,
		RsKnown:     RsKnown,
		RsCommitted: RsCommitted,
		RsHidden:    RsHidden,
		N1:          N1,
		G:           G,
		H:           H,
	}
}

// GetContext concatenates public parameters and returns a corresponding number.
func (k *PubKey) GetContext() *big.Int {
	numbers := make([]*big.Int, len(k.RsKnown)+3)
	numbers[0] = k.N
	numbers[1] = k.S
	numbers[2] = k.Z
	for i, r := range k.RsKnown {
		numbers[i+3] = r
	}
	concatenated := common.ConcatenateNumbers(numbers...)
	return new(big.Int).SetBytes(concatenated)
}

type Org struct {
	ParamSizes                 *CLParams
	Group                      *groups.QRSpecialRSA
	PedersenReceiver           *commitments.PedersenReceiver
	PubKey                     *PubKey
	attributesSpecialRSAPrimes *common.SpecialRSAPrimes
}

func NewOrg(name string, clParamSizes *CLParams) (*Org, error) {
	group, err := groups.NewQRSpecialRSA(clParamSizes.NLength / 2)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	S, Z, RsKnown, RsCommitted, RsHidden, err := generateQuadraticResidues(group, clParamSizes.KnownAttrsNum,
		clParamSizes.CommittedAttrsNum, clParamSizes.HiddenAttrsNum)

	// for commitments of (committed) attributes:
	commitmentReceiver, err := commitments.NewDamgardFujisakiReceiver(clParamSizes.NLength/2, clParamSizes.SecParam)
	if err != nil {
		return nil, fmt.Errorf("error when creating DF commitment receiver: %s", err)
	}

	pubKey := NewPubKey(group.N, S, Z, RsKnown, RsCommitted, RsHidden, commitmentReceiver.QRSpecialRSA.N,
		commitmentReceiver.G, commitmentReceiver.H)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	pedersenParams, err := commitments.GeneratePedersenParams(clParamSizes.RhoBitLen)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen receiver: %s", err)
	}

	return NewOrgFromParams(name, clParamSizes, group.GetSpecialRSAPrimes(), pubKey, pedersenParams,
		commitmentReceiver.QRSpecialRSA.GetSpecialRSAPrimes(), commitmentReceiver.G, commitmentReceiver.H)
}

func NewOrgFromParams(name string, clParamSizes *CLParams, primes *common.SpecialRSAPrimes,
	pubKey *PubKey, pedersenParams *commitments.PedersenParams,
	attributesSpecialRSAPrimes *common.SpecialRSAPrimes, G, H *big.Int) (*Org, error) {
	group, err := groups.NewQRSpecialRSAFromParams(primes)
	if err != nil {
		return nil, fmt.Errorf("error when creating QRSpecialRSA group: %s", err)
	}

	return &Org{
		ParamSizes:                 clParamSizes,
		Group:                      group,
		PubKey:                     pubKey,
		PedersenReceiver:           commitments.NewPedersenReceiverFromParams(pedersenParams),
		attributesSpecialRSAPrimes: attributesSpecialRSAPrimes,
	}, nil
}

func generateQuadraticResidues(group *groups.QRSpecialRSA, knownAttrsNum, committedAttrsNum,
	hiddenAttrsNum int) (*big.Int, *big.Int, []*big.Int,
	[]*big.Int, []*big.Int, error) {
	S, err := group.GetRandomGenerator()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error when searching for QRSpecialRSA generator: %s", err)
	}
	Z := group.Exp(S, common.GetRandomInt(group.Order))

	RsKnown := make([]*big.Int, knownAttrsNum)
	for i, _ := range RsKnown {
		RsKnown[i] = group.Exp(S, common.GetRandomInt(group.Order))
	}

	RsCommitted := make([]*big.Int, committedAttrsNum)
	for i, _ := range RsCommitted {
		RsCommitted[i] = group.Exp(S, common.GetRandomInt(group.Order))
	}

	RsHidden := make([]*big.Int, hiddenAttrsNum)
	for i, _ := range RsHidden {
		RsHidden[i] = group.Exp(S, common.GetRandomInt(group.Order))
	}

	return S, Z, RsKnown, RsCommitted, RsHidden, nil
}
