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

package dlogproofs

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

func TestPartialDLogKnowledge(t *testing.T) {
	group, _ := groups.NewSchnorrGroup(256)

	secret1 := common.GetRandomInt(group.Q)
	x := common.GetRandomInt(group.Q)

	groupOrder := new(big.Int).Sub(group.P, big.NewInt(1))
	a1, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)
	a2, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)

	//b1, _ := dlog.Exponentiate(a1, secret1)
	// we pretend that we don't know x:
	b2 := group.Exp(a2, x)
	proved := ProvePartialDLogKnowledge(group, secret1, a1, a2, b2)

	assert.Equal(t, proved, true, "ProvePartialDLogKnowledge does not work correctly")
}
