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
	rc := NewRawCredential()
	_, err := rc.AddStringAttribute("Name", "John")
	if err != nil {
		t.Errorf("error when setting attribute values: %v", err)
	}

	_, err = rc.AddStringAttribute("Gender", "M")
	if err != nil {
		t.Errorf("error when setting attribute values: %v", err)
	}

	_, err = rc.AddIntAttribute("Age", "122")
	if err != nil {
		t.Errorf("error when setting attribute values: %v", err)
	}

	values := rc.GetAttributeValues()
	attrValues := map[int]string{0: "John", 1: "M", 2: "122"}

	assert.Equal(t, attrValues, values, "raw credential attributes setting does not work")
}
