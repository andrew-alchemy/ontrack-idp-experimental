package frameworks.authn.context;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;

import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;

import com.google.common.base.Function;

import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.authn.context.SubjectContext;

/**
 * This is used to apply an "attribute getter" function to all the principals in a Subject held in a SubjectContext
 * 
 * In our SSO controller we define a Subject and all its principals based on the current (Oauth) authentication
 * This is the tunneled through to the preauth flow where they can be used by code like this that extracts the data and 
 * uses it to expose SAML attributes or control behaviour e.g. in an activationCondition predicate   
 * 
 *  See fw-attribute-resoucres.xml
 * 
 * @author Andrew
 *
 */
public class SubjectContextTenantLookup implements ContextDataLookupFunction<SubjectContext, String> {
	
	private Function<Principal, List<IdPAttributeValue<?>>> attributesValuesFunction; 

	/**
	 * this will be the injected function bean that extracts attribute values from a Principal
	 * @param function
	 */
	public void setAttributeValuesFunction( final Function<Principal, List<IdPAttributeValue<?>>> function) {
		 this.attributesValuesFunction = function;
	}

	/**
	 * this just iterates over all principals in the Subject(s) and gets the attribute value(s) 
	 */
	public String apply(final SubjectContext input) {
		List<IdPAttributeValue<?>> results = new ArrayList<IdPAttributeValue<?>>(1);
		for (Subject subject : input.getSubjects()) {
			for (Principal principal : subject.getPrincipals()) {
				List<IdPAttributeValue<?>> values = (List<IdPAttributeValue<?>>) this.attributesValuesFunction.apply(principal);
				if ((null != values) && (!values.isEmpty())) {
					results.addAll(values);
				}
			}
		}
		if ( results.size() > 0  ) {
			return results.get(0).getValue().toString();
		}
		
		return null;
	}
	
}
