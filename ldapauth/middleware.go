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
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// LdapMiddleware takes in a ILDAP (allows for mocking the actual LDAP calls) and then
// checks if a Basic Auth: Authorization header is present on the context, and that the
// header is valid. If it's invalid or missing, it sends back a WWW-Authenticate challenge
// which allows for non preemptive basic auth to function. If the header is valid, it then
// checks the credentials against LDAP and sets the context with the creds that we get back
// or sends a 401 Unauthorized based on results of underlying LDAP call
func LdapMiddleware(conn ldap.ILDAP) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, password, err := parseAuth(c)
		if err != nil {
			c.Header("WWW-Authenticate", `Basic realm="LDAP"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, "401 Unauthorized")
			return
		}
		creds, err := checkUserPassword(username, password, conn)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "401 Unauthorized")
			return
		}
		c.Set("Creds", creds)
		c.Next()
		return
	}
}

// Essentially reverse engineered Basic Auth for the use of passing credentials
func parseAuth(c *gin.Context) (username string, password string, err error) {
	s := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(s) != 2 {
		err = errors.New("Authorization header malformed for basic auth")
		return username, password, err
	}
	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return username, password, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		err = errors.New("Decoded Authorization header malformed for basic auth")
		return username, password, err
	}
	username = pair[0]
	password = pair[1]

	return username, password, nil
}

func checkUserPassword(username string, password string, conn ldap.ILDAP) (creds []string, err error) {
	valid, creds, err := conn.CheckUserCredentials(username, password)
	if err != nil {
		return creds, err
	}
	if valid != true {
		err = errors.New("Username password invalid")
		return creds, err
	}
	return creds, nil
}

// CheckCreds takes a string (effectively an LDAP group) that is expected
// and checks the Gin context to see if it has that group. This allows for
// fine grained access control and can be used as a handler on any endpoint
// that checks LDAP creds (AKA by calling LdapMiddleware)
func CheckCreds(cred string) gin.HandlerFunc {
	return func(c *gin.Context) {
		creds, _ := c.Get("Creds")
		if contains(creds.([]string), cred) {
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "401 Unauthorized")
		}
	}
}

// contains implementation note - slice outperforms map for comparisons on string less than 5 in length
// probably switch to map if we for some reason ever got a large list of groups to check
// or just redo how we do things in general
func contains(s []string, c string) bool {
	for _, a := range s {
		if a == c {
			return true
		}
	}
	return false
}
