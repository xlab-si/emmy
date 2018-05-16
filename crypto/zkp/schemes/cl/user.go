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
)

type User struct {
	ParamSizes     *CLParamSizes
	PubKey         *PubKey
	PedersenParams *commitments.PedersenParams               // for pseudonyms - nym is a commitment to the master secret
	Committers     map[string]*commitments.PedersenCommitter // for generating nyms
	masterSecret   *big.Int
	attrs          []*big.Int
}

func NewUser(clParamSizes *CLParamSizes, clPubKey *PubKey, pedersenParams *commitments.PedersenParams) *User {
	return &User{
		ParamSizes:     clParamSizes,
		PubKey:         clPubKey,
		Committers:     make(map[string]*commitments.PedersenCommitter),
		PedersenParams: pedersenParams,
		attrs:          []*big.Int{big.NewInt(7), big.NewInt(6), big.NewInt(5)}, // TODO attributes should be read from somewhere and the structure should be loaded too
	}
}

func (u *User) GenerateMasterSecret() {
	u.masterSecret = common.GetRandomInt(u.PedersenParams.Group.Q)
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym(nymName string) (*big.Int, error) {
	committer := commitments.NewPedersenCommitter(u.PedersenParams)
	com, err := committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	u.Committers[nymName] = committer
	return com, nil
}
