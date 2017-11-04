# ontrack-idp
OAuth-SAML bridge using Shibboleth IDP

## JBoss Quirks
Set the system property to the base folder where the git repository is cloned.

e.g. "-Didp.home=C:/ontrack/idp" 

Note this override in idp.properties
```
idp.xml.securityManager=org.apache.xerces.util.SecurityManager
```

See also the setting in the EAR file META-INF/boss-deployment-structure.xml
```
<sub-deployment name="idp.war">
	<dependencies>
		<module name="org.apache.xerces" slot="main" export="true" optional="false"/>
	</dependencies>
	<exclusions>
        <module name="org.slf4j" />
        <module name="org.slf4j.impl" />
    </exclusions>
</sub-deployment>
```

Make sure the xerces module is available (in Eclipse that's Window/Preferences/Server/Runtime Environments/Classpath Entries  - you know exactly where you might think it would be FFS)