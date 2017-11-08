package frameworks.authn.context;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.security.auth.Subject;

import org.opensaml.messaging.context.navigate.ContextDataLookupFunction;

import com.google.common.base.Function;

import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.authn.context.SubjectContext;

public class SubjectContextTenantLookup implements ContextDataLookupFunction<SubjectContext, String> {
	
	private Function<Principal, List<IdPAttributeValue<?>>> attributesValuesFunction; 

	public void setAttributeValuesFunction( final Function<Principal, List<IdPAttributeValue<?>>> function) {
		 this.attributesValuesFunction = function;
	}

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
