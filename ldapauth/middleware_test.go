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
	"github.com/gin-gonic/gin"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupRouter() *gin.Engine {
	ldap := MockLDAP{}
	r := gin.New()
	r.Use(LdapMiddleware(&ldap))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, "OK")
	})
	return r
}

func setupRouterCreds(cred string) *gin.Engine {
	ldap := MockLDAP{}
	r := gin.New()
	r.Use(LdapMiddleware(&ldap))
	r.GET("/health", CheckCreds(cred), func(c *gin.Context) {
		c.JSON(200, "OK")
	})
	return r
}

func TestLdapMiddleware(t *testing.T) {
	r := setupRouter()
	req := httptest.NewRequest("GET", "/health", nil)
	req.SetBasicAuth("admin", "admin123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Code should be: %d but was %d", http.StatusOK, w.Code)
	}
}

func TestLdapMiddlewareCheckCreds(t *testing.T) {
	r := setupRouterCreds("sonatype-license-api")
	req := httptest.NewRequest("GET", "/health", nil)
	req.SetBasicAuth("admin", "admin123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Code should be: %d but was %d", http.StatusOK, w.Code)
	}
}

func TestLdapMiddlewareCheckCredsNoCreds(t *testing.T) {
	r := setupRouterCreds("fictional")
	req := httptest.NewRequest("GET", "/health", nil)
	req.SetBasicAuth("admin", "admin123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Code should be: %d but was %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLdapMiddlewareThrowError(t *testing.T) {
	r := setupRouter()
	req := httptest.NewRequest("GET", "/health", nil)
	req.SetBasicAuth("", "")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Code should be: %d but was %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLdapMiddlewareInvalidCreds(t *testing.T) {
	r := setupRouter()
	req := httptest.NewRequest("GET", "/health", nil)
	req.SetBasicAuth("homerjsimpson", "donut")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Code should be: %d but was %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLdapMiddlewareBadBasicAuthValue(t *testing.T) {
	r := setupRouter()
	req := httptest.NewRequest("GET", "/health", nil)
	// Header generated at: https://www.base64encode.org/ with string "bogusthing"
	req.Header.Add("Authorization", "Basic Ym9ndXN0aGluZw==")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Code should be: %d but was %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLdapMiddlewareMalformedAuthHeader(t *testing.T) {
	r := setupRouter()
	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Add("Authorization", "Basic totally bogus")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Code should be: %d but was %d", http.StatusUnauthorized, w.Code)
	}
}

func TestLdapMiddlewareNoBasicAuth(t *testing.T) {
	r := setupRouter()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Code should be: %d but was %d", http.StatusUnauthorized, w.Code)
	}

	if w.Header().Get("WWW-Authenticate") != `Basic realm="LDAP"` {
		t.Errorf("WWW-Authenticate header not being sent as challenge")
	}
}
