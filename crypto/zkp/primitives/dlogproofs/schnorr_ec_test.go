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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
)

func TestDLogKnowledgeEC(t *testing.T) {
	group := groups.NewECGroup(groups.P256)

	exp1 := common.GetRandomInt(group.Q)
	a1 := group.ExpBaseG(exp1)

	secret := common.GetRandomInt(group.Q)
	b1 := group.Exp(a1, secret)

	proved, err := ProveECDLogKnowledge(secret, a1, b1, groups.P256)
	if err != nil {
		assert.Equal(t, proved, false, "ECDLogEquality proof failed: %v", err)
	}

	assert.Equal(t, proved, true, "ECDLogEquality does not work correctly")
}
