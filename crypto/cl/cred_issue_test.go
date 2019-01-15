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

func TestCL(t *testing.T) {
	params := GetDefaultParamSizes()

	org, err := NewOrg(params)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	masterSecret := org.PubKey.GenerateUserMasterSecret()

	attr1 := NewAttribute("Name", "string", true, nil)
	attr2 := NewAttribute("Gender", "string", true, nil)
	attr3 := NewAttribute("Age", "int", false, nil)
	rawCred := NewRawCredential([]Attribute{*attr1, *attr2, *attr3})
	attrValues := []string{"Jack", "M", "122"}
	err = rawCred.SetAttributeValues(attrValues)
	if err != nil {
		t.Errorf("error when setting attribute values: %v", err)
	}

	credManager, err := NewCredManager(params, org.PubKey, masterSecret, rawCred)
	if err != nil {
		t.Errorf("error when creating a user: %v", err)
	}

	credManagerPath := "../client/testdata/credManager.gob"
	WriteGob(credManagerPath, credManager)

	credIssueNonceOrg := org.GetCredIssueNonce()

	credReq, err := credManager.GetCredRequest(credIssueNonceOrg)
	if err != nil {
		t.Errorf("error when generating credential request: %v", err)
	}

	res, err := org.IssueCred(credReq)
	if err != nil {
		t.Errorf("error when issuing credential: %v", err)
	}

	// Store record to db
	mockDb := NewMockRecordManager()
	if err := mockDb.Store(credReq.Nym, res.Record); err != nil {
		t.Errorf("error saving record to db: %v", err)
	}

	userVerified, err := credManager.Verify(res.Cred, res.AProof)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}
	assert.Equal(t, true, userVerified, "credential proof not valid")

	// Before updating a credential, create a new Org object (obtaining and updating
	// credential usually don't happen at the same time)
	org, err = NewOrgFromParams(params, org.PubKey, org.SecKey)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	// create new CredManager (updating or proving usually does not happen at the same time
	// as issuing)
	ReadGob(credManagerPath, credManager)

	// Modify raw credential and get updated credential from an organization

	attrValues = []string{"John", "M", "122"}
	rawCred.SetAttributeValues(attrValues)
	// refresh credManager with new credential values, works only for known attributes
	credManager.RefreshRawCredential(rawCred)

	rec, err := mockDb.Load(credManager.Nym)
	if err != nil {
		t.Errorf("error saving record to db: %v", err)
	}
	res1, err := org.UpdateCred(credManager.Nym, rec, credReq.Nonce, rawCred)
	if err != nil {
		t.Errorf("error when updating credential: %v", err)
	}
	if err := mockDb.Store(credManager.Nym, res1.Record); err != nil {
		t.Errorf("error saving record to db: %v", err)
	}

	userVerified, err = credManager.Verify(res1.Cred, res1.AProof)
	if err != nil {
		t.Errorf("error when verifying updated credential: %v", err)
	}
	assert.Equal(t, true, userVerified, "credential update failed")

	// Some other organization which would like to verify the credential can instantiate org without sec key.
	// It only needs pub key of the organization that issued a credential.
	org, err = NewOrgFromParams(params, org.PubKey, nil)
	if err != nil {
		t.Errorf("error when generating CL org: %v", err)
	}

	revealedKnownAttrsIndices := []int{1}         // reveal only the second known attribute
	revealedCommitmentsOfAttrsIndices := []int{0} // reveal only the commitment of the first attribute (of those of which only commitments are known)

	nonce := org.GetProveCredNonce()
	randCred, proof, err := credManager.BuildProof(res1.Cred, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, nonce)
	if err != nil {
		t.Errorf("error when building credential proof: %v", err)
	}

	cVerified, err := org.ProveCred(randCred.A, proof, revealedKnownAttrsIndices,
		revealedCommitmentsOfAttrsIndices, rawCred, credManager.CommitmentsOfAttrs)
	if err != nil {
		t.Errorf("error when verifying credential: %v", err)
	}

	assert.Equal(t, true, cVerified, "credential verification failed")
}
