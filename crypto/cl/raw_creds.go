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
	Index int
	Name  string
	Type  string // currently only "string" and "int" types are supported
	Known bool
	Value *big.Int // this value is set by SetAttributeValue and is used internally in CL scheme
}

func NewAttribute(index int, name, attrType string, known bool, value *big.Int) *Attribute {
	return &Attribute{
		Index: index,
		Name:  name,
		Type:  attrType,
		Known: known,
		Value: value,
	}
}

// RawCredential presents credential as to be used by application that executes CL scheme to prove possesion
// of an anonymous credential.
type RawCredential struct {
	attributes      map[int]*Attribute
	attrNameToIndex map[string]int
}

func NewRawCredential() *RawCredential {
	return &RawCredential{
		attributes:      make(map[int]*Attribute),
		attrNameToIndex: make(map[string]int),
	}
}

func (c *RawCredential) InsertAttribute(index int, name, attrType string, known bool) {
	c.attrNameToIndex[name] = index
	c.attributes[index] = NewAttribute(index, name, attrType, known, nil)
}

func (c *RawCredential) AddAttribute(name, attrType string, known bool, value string) error {
	index := len(c.attributes)
	c.attrNameToIndex[name] = index
	c.attributes[index] = NewAttribute(index, name, attrType, known, nil)
	return c.SetAttributeValue(name, value)
}

// SetAttributeValue converts and set the attribute value to *big.Int which is then used internally
// by CL scheme.
func (c *RawCredential) SetAttributeValue(name string, value string) error {
	index := c.attrNameToIndex[name]
	attr := c.attributes[index]
	if attr.Type == "string" {
		attr.Value = new(big.Int).SetBytes([]byte(value))
	} else if attr.Type == "int" {
		v, success := new(big.Int).SetString(value, 10)
		if !success {
			return fmt.Errorf("cannot convert attribute to *big.Int: %s", value)
		}
		attr.Value = v
	} else {
		return fmt.Errorf("attribute type is not supported: %s", attr.Type)
	}

	return nil
}

func (c *RawCredential) GetAttributes() map[int]*Attribute {
	return c.attributes
}

// GetAttributeValues converts attribute values from *big.Ints (used by CL scheme) to the initial form,
// as they are used in the application that runs CL scheme.
func (c *RawCredential) GetAttributeValues() map[int]string {
	attrValues := make(map[int]string)
	for i, attr := range c.attributes {
		if attr.Type == "string" {
			attrValues[i] = string(c.attributes[i].Value.Bytes())
		} else if attr.Type == "int" {
			attrValues[i] = c.attributes[i].Value.String()
		}
	}

	return attrValues
}

// GetKnownValues returns *big.Int values of known attributes.
// The returned elements are ordered by attribute's index.
func (c *RawCredential) GetKnownValues() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.attributes); i++ { // avoid range to have attributes in proper order
		attr := c.attributes[i]
		if attr.Known {
			values = append(values, attr.Value)
		}
	}

	return values
}

// GetCommittedValues returns *big.Int values of committed attributes.
// The returned elements are ordered by attribute's index.
func (c *RawCredential) GetCommittedValues() []*big.Int {
	var values []*big.Int
	for i := 0; i < len(c.attributes); i++ { // avoid range to have attributes in proper order
		attr := c.attributes[i]
		if !attr.Known {
			values = append(values, attr.Value)
		}
	}

	return values
}
