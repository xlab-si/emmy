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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRawCreds(t *testing.T) {
	attr1 := NewAttribute("Name", "string", true, nil)
	attr2 := NewAttribute("Gender", "string", true, nil)
	attr3 := NewAttribute("Age", "int", true, nil)
	rc := NewRawCredential([]Attribute{*attr1, *attr2, *attr3})
	// all values need to be passed to SetAttributeValues as strings,
	// attrs of Type int are then set to have Value of *big.Int
	attrValues := []string{"John", "M", "122"}
	err := rc.SetAttributeValues(attrValues)
	if err != nil {
		t.Errorf("error when setting attribute values: %v", err)
	}

	values := rc.GetAttributeValues()

	assert.Equal(t, attrValues, values, "raw credential attributes setting does not work")
}
