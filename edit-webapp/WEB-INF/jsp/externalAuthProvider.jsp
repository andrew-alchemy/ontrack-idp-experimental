<%@ page language="java" contentType="text/plain; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page trimDirectiveWhitespaces="true" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Collection" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.util.Enumeration" %>
<%@ page import="javax.security.auth.Subject" %>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="javax.servlet.http.HttpServletResponse" %>
<%@ page import="net.shibboleth.idp.authn.ExternalAuthentication" %>
<%@ page import="net.shibboleth.idp.authn.ExternalAuthenticationException" %>
<%@ page import="net.shibboleth.idp.authn.principal.UsernamePrincipal" %>
<%@ page import="net.shibboleth.utilities.java.support.primitive.StringSupport" %>

<%@ page import="org.slf4j.Logger" %>
<%@ page import="org.slf4j.LoggerFactory" %>
<%!
/*
should receive these request attributes

opensamlProfileRequestContext ProfileRequestContext	Access to full request context tree
forceAuthn	Boolean	Whether the requester asked for re-authentication
isPassive	Boolean	Whether the requested asked for passive authentication
relyingParty	String	Name of the relying party requesting authentication
extended 3.2	Boolean	Whether this login flow has been invoked as an extension of another login flow
authnMethod (deprecated)	String	Identifier for an authentication method supported by the flow

and return these 

principalName	String	Name of authenticated subject to use as the login result
principal	java.security.Principal	Java Principal object to use as the login result
subject	java.security.Subject	Java Subject object to use as the login result
authnError	String	Error message to return in place of a successful login
authnException	Exception	Explicit exception object to return in place of a successful login
authnInstant	org.joda.time.DateTime	Exact time of authentication to report back
doNotCache	Boolean	
If true, prevents the result from being saved for future use for SSO
previousResult 3.3	Boolean	If true, the "new" AuthenticationResult is created with the "previousResult" flag set to true (mainly impacts auditing)

*/

final Logger log = LoggerFactory.getLogger(net.shibboleth.idp.authn.ExternalAuthentication.class);
final String HEADER_NAME_REMOTE_USER = "REMOTE_USER";
%>

<html>
hello mum
1<% out.print( request.getQueryString()); %><br/>
1<% out.print( request.getParameter("token") ); %><br/>
2<% out.print( request.getLocalName()); %><br/>
3<% out.print( request.getRemoteUser()); %><br/>
4<% out.print( request.getRemoteHost()); %><br/>
5<% out.print( request.getContextPath()); %><br/>
 
</html>

<%
try {
	log.info("Servlet query string" + request.getQueryString());
	log.info("Servlet query param token " + request.getParameter("token") );

	
	final String id = ExternalAuthentication.startExternalAuthentication(request);
	
	final Subject subject = new Subject();
	log.info("REMOTE_USER header {}", request.getHeader(HEADER_NAME_REMOTE_USER));
	String username = request.getHeader(HEADER_NAME_REMOTE_USER);
	log.info("Servlet remote user {}", request.getRemoteUser());
	if (StringSupport.trimOrNull(username) == null) {
		username = request.getRemoteUser();
	}
	
	username="jdoe";
	
	if (StringSupport.trimOrNull(username) != null) {
		subject.getPrincipals().add(new UsernamePrincipal(username));
		log.info("User identity extracted from REMOTE_USER: {}", username);
	} else {
		log.info("No remote user provided");
	}

	final Enumeration<String> headerNames = request.getHeaderNames();
	while (headerNames.hasMoreElements()) {
		final String header = headerNames.nextElement();
		final String value = request.getHeader(header);
		log.info("Header name {} has value {}", header, value);
		if (value != null && !value.isEmpty()) {
			//subject.getPrincipals().add(new ShibHeaderPrincipal(header, value));
			log.info("Header {} added to the set of Principals", header);
		}
	}

	final Enumeration<String> attributeNames = request.getAttributeNames();
	while (attributeNames.hasMoreElements()) {
		final String attribute = attributeNames.nextElement();
		log.info("Attribute name {} has value {}", attribute, request.getAttribute(attribute));
	}

	request.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);
	log.info("Subject populated and added to the request");
	ExternalAuthentication.finishExternalAuthentication(id, request, response);
} catch (final ExternalAuthenticationException e) {
	log.info("External authentication exception", e);
}

%>
