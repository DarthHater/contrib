<!-- 
Copyright 2018 Sonatype

Licensed under the Apache License, Version 2.0 (the "License"); 
you may not use this file except in compliance with the License. 
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software 
distributed under the License is distributed on an "AS IS" BASIS, 
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
See the License for the specific language governing permissions and 
limitations under the License.  
-->

LDAP Auth middleware for go gonic.

In the /example folder you'll find a simple lil app that uses this middleware.

In order to set this up, you'll want to ensure the following defaults are set to the correct values for your org.

```go
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
```

As well, pay special attention to the LdapGroups, in my basic example there is a read and write group, you'll need your users in LDAP to be associated with the groups you choose in order to get all the access bits working. You can tweak this to your liking, or alternatively send a PR to make this more extensible.

The middleware uses Basic Auth to get credentials, you'll want to set up any app the uses this on https as Basic Auth over http is not secure.

Author: [Sonatype](https://www.sonatype.com/)
Contributor: [Sonatype Nexus Community](https://github.com/sonatype-nexus-community)
