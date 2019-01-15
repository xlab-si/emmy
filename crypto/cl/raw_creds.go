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
)

// Attribute is part of a credential (RawCredential). In the case of digital identity credential,
// attributes could be for example Name, Gender, Date of Birth. In the case of a credential allowing
// access to some internet service (like electronic newspaper), attributes could be
// Type (for example only news related to politics) of the service and Date of Expiration.
type Attribute struct {
	Name  string
	Type  string // currently only "string" and "int" types are supported
	Known bool
	Value *big.Int // this value is set by SetAttributeValues and is used internally in CL scheme
}

func NewAttribute(name, attrType string, known bool, value *big.Int) *Attribute {
	return &Attribute{
		Name:  name,
		Type:  attrType,
		Known: known,
		Value: value,
	}
}

// RawCredential presents credential as to be used by application that executes CL scheme to prove possesion
// of an anonymous credential.
type RawCredential struct {
	Attributes []Attribute
}

func NewRawCredential(attrs []Attribute) *RawCredential {
	return &RawCredential{
		Attributes: attrs,
	}
}

// SetAttributeValues converts and set the attribute values to *big.Ints which are then used internally
// by CL scheme.
func (c *RawCredential) SetAttributeValues(attrValues []string) error {
	for i, attr := range c.Attributes {
		if attr.Type == "string" {
			c.Attributes[i].Value = new(big.Int).SetBytes([]byte(attrValues[i]))
		} else if attr.Type == "int" {
			v, success := new(big.Int).SetString(attrValues[i], 10)
			if !success {
				return fmt.Errorf("cannot convert attribute to *big.Int: %s", attrValues[i])
			}
			c.Attributes[i].Value = v
		} else {
			return fmt.Errorf("attribute type is not supported: %s", attr.Type)
		}
	}

	return nil
}

// GetAttributeValues converts attribute values from *big.Ints (used by CL scheme) to the initial form,
// as they are used in the application that runs CL scheme.
func (c *RawCredential) GetAttributeValues() []string {
	attrValues := make([]string, len(c.Attributes))
	for i, attr := range c.Attributes {
		if attr.Type == "string" {
			attrValues[i] = string(c.Attributes[i].Value.Bytes())
		} else if attr.Type == "int" {
			attrValues[i] = c.Attributes[i].Value.String()
		}
	}

	return attrValues
}

// GetKnownValues returns *big.Int values of known attributes.
func (c *RawCredential) GetKnownValues() []*big.Int {
	var values []*big.Int
	for _, attr := range c.Attributes {
		if attr.Known {
			values = append(values, attr.Value)
		}
	}

	return values
}

// GetCommittedValues returns *big.Int values of committed attributes.
func (c *RawCredential) GetCommittedValues() []*big.Int {
	var values []*big.Int
	for _, attr := range c.Attributes {
		if !attr.Known {
			values = append(values, attr.Value)
		}
	}

	return values
}
