package frameworks.sso.app;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.annotation.security.PermitAll;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import frameworks.security.authentication.TenantContextHolder;
import frameworks.security.core.ONTrackUserDetails;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.authn.principal.IdPAttributePrincipal;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.attribute.StringAttributeValue;

/**
 * The bridge code in the IDP application that is secured by OAuth
 * All this does is forward the request to the IDP unsolicted SSO flow
 * 
 * The magic is simply that this endpoint is secured by Oauth and that authentication is used in a preauthentication flow in the IDP
 * In this way we can convert OAuth to SAML
 * 
 * @author Andrew
 *
 */
@Controller
@RequestMapping("/ontracksso")
public class SSOController {
	final Logger log = LoggerFactory.getLogger(SSOController.class);//NB goes to the local idp logs
	
	//the unsolicited SSO endpoint
	final String IDP_UNSOLICITED_SSO_URI = "/profile/SAML2/Unsolicited/SSO";
	
	/**
	 * Because the request is now buried in a wrapper we can NOT add the parameters in this code as part of the forward
	 * They must be provided as part of the original inbound request to this endpoint
	 * See parameters at https://wiki.shibboleth.net/confluence/display/IDP30/UnsolicitedSSOConfiguration
	 * 
	 * 
	 * @param auth
	 * @param request
	 * @param spEntityId
	 * @param relayState
	 * @param shire
	 * @param time
	 * @return
	 */
	@RequestMapping(value="/go")
	@PermitAll
	public String doUnsolicitedSSO(
			Authentication auth,
			HttpServletRequest request,
			@RequestParam(value="providerId", required=true) String spEntityId,
			@RequestParam(value="target", required=false) String relayState,
			@RequestParam(value="shire", required=false) String shire,
			@RequestParam(value="time", required=false) String time
			) {
		
		//this endpoint is tenant-aware (filtered by the TenantContextFilter) and is expected to be invoked from a tenant-specific URL
		//NB. make sure the tenant resolver bean in this application is maintained !!!!
		String tenant = TenantContextHolder.getContext().getCd();
		log.debug("Tenant cd:" + tenant);
		
		log.debug("OAuth Token: " + request.getParameter("access_token") ); //the Oauth token used 
		log.debug("providerId " + spEntityId );

		//auth will be of type OAuth2Authentication
		//Object oauth = auth.getDetails(); //should be an instance of OAuth2AuthenticationDetails
		//String token= ((OAuth2AuthenticationDetails)oauth).getTokenValue()
		Object principal = auth.getPrincipal(); //should be an instance of OnTrackUserDetails
		if ( principal instanceof ONTrackUserDetails ) {
			ONTrackUserDetails onUser = (ONTrackUserDetails)principal;
			log.debug("User userId:" + onUser.getUserId() );
			log.debug("User username:" + onUser.getUsername() );
			log.debug("User roleCd:" + onUser.getRoleCd() );
			log.debug("User dagId:" + onUser.getDagId());
			
			//this is critical so that SWF can see the tenant
			//It can access it via EL "externalContext.getRequestMap().get('ONTRACK_TENANT')"
			request.setAttribute("ONTRACK_TENANT", tenant);

			//Username principal
			Set<Principal> principals = new HashSet<Principal>();
			principals.add( new UsernamePrincipal( onUser.getUsername() ) );

			//IdpAttribute principals
			IdPAttribute attr = new IdPAttribute("Tenant");
			List<StringAttributeValue> attrValues = new ArrayList<StringAttributeValue>(1);
			attrValues.add( new StringAttributeValue(tenant) );
			attr.setValues( attrValues );

			principals.add( new IdPAttributePrincipal(attr) );
			
			
			Subject subject = new Subject(false, principals, Collections.emptySet(), Collections.emptySet());
			request.setAttribute("ONTRACK_SUBJECT", subject);
			
		} else {
			log.debug("Unrecognized user:" + principal );
		}
		
		//request.getRequestDispatcher(IDP_UNSOLICITED_SSO_URI).forward(request, response);

		return "forward:/"+IDP_UNSOLICITED_SSO_URI;//see note above about trying to add parameters
	}
}

