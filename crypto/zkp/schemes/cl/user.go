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
	"math/big"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/commitments"
	"fmt"
)

type User struct {
	masterSecret               *big.Int
	nyms map[string]*big.Int
	committer *commitments.DamgardFujisakiCommitter
}

func NewUser(clPubKey *CLPubKey, sec_param int) *User {
	nyms := make(map[string]*big.Int)

	// Pedersen or DamgardFujisaki committer to be used here?

	committer := commitments.NewDamgardFujisakiCommitter(clPubKey.N, clPubKey.S, clPubKey.Z,
		clPubKey.N, sec_param)

	return &User{
		nyms: nyms,
		committer: committer,
	}
}

func (u *User) GenerateMasterSecret() {
	u.masterSecret = common.GetRandomInt(u.CLParams.CommitmentGroup.Q)
}

// GenerateNym creates a pseudonym to be used with a given organization. Multiple pseudonyms
// can be generated for the same organization (on the contrary domain pseudonym can be only
// one per organization - not implemented yet). Authentication can be done with respect to
// the pseudonym or not (depends on the server configuration).
func (u *User) GenerateNym(orgName string) (*big.Int, error) {
	com, err := u.committer.GetCommitMsg(u.masterSecret)
	if err != nil {
		return nil, fmt.Errorf("error when creating Pedersen commitment: %s", err)
	}
	u.nyms[orgName] = com
	return com, nil
}



