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
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
)

func TestDLogKnowledge(t *testing.T) {
	group := config.LoadGroup("pseudonymsys")

	secret := common.GetRandomInt(group.Q)
	groupOrder := new(big.Int).Sub(group.P, big.NewInt(1))
	g1, _ := common.GetGeneratorOfZnSubgroup(group.P, groupOrder, group.Q)
	t1 := group.Exp(g1, secret)
	proved := ProveDLogKnowledge(secret, g1, t1, group)

	assert.Equal(t, proved, true, "DLogKnowledge does not work correctly")
}
