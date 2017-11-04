<%@ page language="java" contentType="text/plain; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ page trimDirectiveWhitespaces="true" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Collection" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.util.Enumeration" %>
<%@ page import="javax.security.auth.Subject" %>
<%@ page import="javax.servlet.http.HttpServletRequest" %>
<%@ page import="javax.servlet.http.HttpServletResponse" %>
<%@ page import="org.slf4j.Logger" %>
<%@ page import="org.slf4j.LoggerFactory" %>
<%!
/**/
final Logger log = LoggerFactory.getLogger(net.shibboleth.idp.authn.ExternalAuthentication.class);
String PROVIDER_ID;
final String IDP_UNSOLICITED_SSO_URI = "/profile/SAML2/Unsolicited/SSO";
%>
<%
	log.info("MY SSO START!!!!!!!!!!");
	log.info("Servlet query string" + request.getQueryString());
	log.info("Servlet query param token " + request.getParameter("access_token") );
	
	String sp = request.getParameter("sp");
	if ( "R".equals( sp ) ) {
		PROVIDER_ID = "https://sp.testshib.org/shibboleth-sp";
	} else {
		PROVIDER_ID = "https://tapp.frameworks.local:9443/wisp/saml/metadata";
	}
	log.info("going to  " + IDP_UNSOLICITED_SSO_URI );
	log.info("with provider " + PROVIDER_ID );
	
	pageContext.setAttribute("token", request.getParameter("access_token"), PageContext.REQUEST_SCOPE);
%>
<jsp:forward page="/profile/SAML2/Unsolicited/SSO">
  <jsp:param name="providerId" value="https://sp.testshib.org/shibboleth-sp"/>
</jsp:forward>