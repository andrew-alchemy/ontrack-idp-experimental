# ontrack-idp
OAuth-SAML bridge using Shibboleth IDP

## JBoss Quirks
Set the system property to the base folder where the git repository is cloned.

e.g. "-Didp.home=C:/ontrack/idp" 

Note this override in idp.properties
```
idp.xml.securityManager=org.apache.xerces.util.SecurityManager
```

NB. this is not deployed as a component of the EAR but rather a separate WAR in the same manner as reports or integration.


Make sure the xerces module is available (in Eclipse that's Window/Preferences/Server/Runtime Environments/Classpath Entries  - you know exactly where you might think it would be FFS)
