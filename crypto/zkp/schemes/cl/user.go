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
	"math/rand"
	"time"

	"github.com/xlab-si/emmy/crypto/commitments"
	"github.com/xlab-si/emmy/crypto/common"
)

type User struct {
	Params             *CLParams
	PubKey             *PubKey
	PedersenParams     *commitments.PedersenParams              // for pseudonyms - nym is a commitment to the master secret
	Committers         map[int32]*commitments.PedersenCommitter // for generating nyms
	masterSecret       *big.Int
	knownAttrs         []*big.Int                              // attributes that are known to the credential receiver and issuer
	committedAttrs     []*big.Int                              // attributes for which the issuer knows only commitment
	hiddenAttrs        []*big.Int                              // attributes which are known only to the credential receiver
	attrsCommitters    []*commitments.DamgardFujisakiCommitter // committers for committedAttrs
	commitmentsOfAttrs []*big.Int                              // commitments of committedAttrs
}

func checkAttributesLength(attributes []*big.Int, params *CLParams) bool {
	for _, attr := range attributes {
		if attr.BitLen() > params.AttrBitLen {
			return false
		}
	}

	return true
}

func NewUser(clParams *CLParams, clPubKey *PubKey, pedersenParams *commitments.PedersenParams,
	knownAttrs, committedAttrs, hiddenAttrs []*big.Int) (*User, error) {
	if !checkAttributesLength(knownAttrs, clParams) || !checkAttributesLength(committedAttrs, clParams) ||
		!checkAttributesLength(hiddenAttrs, clParams) {
		return nil, fmt.Errorf("attributes length not ok")
	}

	attrsCommitters := make([]*commitments.DamgardFujisakiCommitter, len(committedAttrs))
	commitmentsOfAttrs := make([]*big.Int, len(committedAttrs))
	for i, attr := range committedAttrs {
		committer := commitments.NewDamgardFujisakiCommitter(clPubKey.N1, clPubKey.H, clPubKey.G,
			clPubKey.N1, clParams.SecParam)
		com, err := committer.GetCommitMsg(attr)
		if err != nil {
			return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
		}
		commitmentsOfAttrs[i] = com
		attrsCommitters[i] = committer
	}
	rand.Seed(time.Now().UTC().UnixNano())

	return &User{
		Params:             clParams,
		PubKey:             clPubKey,
		Committers:         make(map[int32]*commitments.PedersenCommitter),
		PedersenParams:     pedersenParams,
		knownAttrs:         knownAttrs,
		committedAttrs:     committedAttrs,
		hiddenAttrs:        hiddenAttrs,
		commitmentsOfAttrs: commitmentsOfAttrs,
		attrsCommitters:    attrsCommitters,
		masterSecret:       common.GetRandomInt(pedersenParams.Group.Q),
	}, nil
}

type Nym struct {
	Id         int32    // nym identifier
	Commitment *big.Int // actual nym that will be known to the organisation - it is in the form of Pedersen commitment
}

func NewNym(commitment *big.Int) *Nym {
	return &Nym{
		Id:         rand.Int31(),
		Commitment: commitment,
	}
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym() (*Nym, error) {
	committer := commitments.NewPedersenCommitter(u.PedersenParams)
	com, err := committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	nym := NewNym(com)
	u.Committers[nym.Id] = committer
	return nym, nil
}
