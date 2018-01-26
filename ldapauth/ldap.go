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
	"fmt"
	"gopkg.in/ldap.v2"
)

// ILDAP interface to allow for LDAP and MockLDAP to be passed in to other functions interchangeably
type ILDAP interface {
	CheckUserCredentials(username string, password string) (verified bool, creds []string, err error)
}

// LDAP struct to allow attachment of new methods, and as well allows you to set
// * LdapURL string
// * LdapProtocol string
// * LdapPort string
// * LdapGroups []string
// * LdapUserQuery string
// * LdapBaseDNGroup string
// * LdapFilterMemberOfGroup string
type LDAP struct {
	LdapURL                 string
	LdapProtocol            string
	LdapPort                int
	LdapGroups              []string
	LdapUserQuery           string
	LdapBaseDNGroup         string
	LdapFilterMemberOfGroup string
}

func (l *LDAP) connect() (conn *ldap.Conn, err error) {
	conn, err = ldap.Dial(l.LdapProtocol, fmt.Sprintf("%s:%d", l.LdapURL, l.LdapPort))
	if err != nil {
		return conn, err
	}

	return conn, nil
}

// CheckUserCredentials accepts a username and password, and will query LDAP to first find the user, then check if the password is valid.
// The method returns false if the user creds are invalid, and returns true if they are valid
func (l *LDAP) CheckUserCredentials(username string, password string) (verified bool, creds []string, err error) {
	verified = false
	conn, err := l.connect()
	if err != nil {
		return verified, creds, err
	}
	defer conn.Close()

	// Bind as user to LDAP to see if user/pass is valid
	userdn := fmt.Sprintf(l.LdapUserQuery, username)
	err = conn.Bind(userdn, password)
	if err != nil {
		return verified, creds, err
	}
	verified = true

	for _, element := range l.LdapGroups {
		searchRequest := ldap.NewSearchRequest(
			l.LdapBaseDNGroup,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			fmt.Sprintf(l.LdapFilterMemberOfGroup, element, username),
			[]string{"dn", "cn"},
			nil,
		)

		sr, err := conn.Search(searchRequest)
		if err != nil {
			return verified, creds, err
		}

		if len(sr.Entries) > 0 {
			creds = append(creds, sr.Entries[0].GetAttributeValue("cn"))
		}
	}

	if len(creds) > 0 {
		return verified, creds, nil
	}
	err = errors.New("User belongs to no valid groups")
	return verified, creds, err
}
