// Copyright 2018 Sonatype

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldapauth

import (
	"errors"
)

// MockLDAP is for using when you don't want to actually query LDAP, or alternatively if you don't want to test
// LDAP as a part of testing another package
type MockLDAP struct {
}

// CheckUserCredentials is mocked out for our ITs, let's us use this struct for testing rather than an actual LDAP server
// and will return valid for admin:admin123 creds
func (l *MockLDAP) CheckUserCredentials(username string, password string) (verified bool, creds []string, err error) {
	if username == "admin" && password == "admin123" {
		creds = append(creds, "read-group")
		creds = append(creds, "write-group")
		verified = true
	} else if username == "" && password == "" {
		err = errors.New("Simulated error from CheckUserCredentials")
		return verified, creds, err
	} else {
		verified = false
	}
	return verified, creds, nil
}
