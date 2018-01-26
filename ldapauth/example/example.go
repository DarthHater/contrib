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

package example

import (
	"github.com/gin-gonic/contrib/ldapauth"
	"github.com/gin-gonic/gin"
)

var (
	conn        ILDAP
	readAccess  string
	writeAccess string
)

func main() {
	readAccess = "read-group"
	writeAccess = "write-group"

	lConn := ldapauth.LDAP{
		LdapURL:                 "ldap.example.com",
		LdapPort:                389,
		LdapProtocol:            "tcp",
		LdapGroups:              []string{readAccess, writeAccess},
		LdapUserQuery:           "cn=%s,ou=people,dc=example,dc=org",
		LdapBaseDNGroup:         "ou=group,dc=example,dc=org",
		LdapFilterMemberOfGroup: "(&(cn=%s)(uniqueMember=cn=%s,ou=people,dc=example,dc=org))",
	}

	conn = &lConn

	r := newServer(conn)
	r.Run(":8000")
}

func newServer(ldapConn ldapauth.ILDAP) (r *gin.Engine) {
	r = setupRouter(ldapConn)
	return r
}

func setupRouter(ldapConn ldapauth.ILDAP) (r *gin.Engine) {
	r = gin.New()
	v1 := r.Group("v1/", ldapauth.LdapMiddleware(ldapConn))

	v1.GET("/health", ldapauth.CheckCreds(readAccess), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "OK"})
	})

	v1.POST("/write", ldapauth.CheckCreds(writeAccess), func(c *gin.Context) {
		c.JSON(http.StatusCreated, gin.H{"message": "Created"})
	})

	return r
}
