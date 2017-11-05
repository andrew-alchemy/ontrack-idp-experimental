package frameworks.jaas;

import java.security.Principal;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * JAAS Login Module
 * @author Andrew
 *
 */
public abstract class BaseLoginModule implements LoginModule {
	 // initial state
    protected Subject			subject;
    protected CallbackHandler	callbackHandler;
    protected Map<String, ?>	sharedState;
    protected Map<String, ?>	options;
    
    // configurable option
    protected boolean	debug	= false;
    
    //
    protected Set<Principal> principals = null;
    
	@Override
	/**
	 * Subject - what we need to authentiate
	 * Callback - container should handle this (process for interacting with user)
	 * SharedState - 
	 * Options - the configuration of this module
	 */
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,  Map<String, ?> options) {
		// Stash our copy of supplied arguments
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
        
        // initialize any configured options
        debug = getOption("debug", debug);
	}

	 /**
     * Get a boolean option from the module's options.
     *
     * @param name Name of the option
     * @param dflt Default value for the option
     * @return The boolean value of the options object.
     */
    protected boolean getOption(String name, boolean dflt) {
        String opt = ((String) options.get(name));
        
        if (opt == null) return dflt;
        
        opt = opt.trim();
        if (opt.equalsIgnoreCase("true") || opt.equalsIgnoreCase("yes") || opt.equals("1"))
            return true;
        else if (opt.equalsIgnoreCase("false") || opt.equalsIgnoreCase("no") || opt.equals("0"))
            return false;
        else
            return dflt;
    }
    
    /**
     * Get a numeric option from the module's options.
     *
     * @param name Name of the option
     * @param dflt Default value for the option
     * @return The boolean value of the options object.
     */
    public int getOption(String name, int dflt) {
        String opt = ((String) options.get(name));
        if (opt == null) return dflt;
        try { dflt = Integer.parseInt(opt); } catch (Exception e) {
            e.printStackTrace();
        }
        return dflt;
    }
    
    /**
     * Get a String option from the module's options.
     *
     * @param name Name of the option
     * @param dflt Default value for the option
     * @return The String value of the options object.
     */
    public String getOption(String name, String dflt) {
        String opt = (String) options.get(name);
        return opt == null ? dflt : opt;
    }
	
	
	
	@Override
	/**
	 * Authenticate the user
	 * This invokes the callbacks to get the name and password
	 * and then validates those credentials
	 *
	 * @return true in all cases since this <code>LoginModule</code> should not be ignored.
	 * @exception FailedLoginException if the authentication fails. <p>
	 * @exception LoginException if this <code>LoginModule</code> is unable to perform the authentication.
	 */
	public boolean login() throws LoginException {
		// username and password
		String	username;
		char	password[] = null;

		try {
			// prompt for a username and password
			if (callbackHandler == null)
				throw new LoginException("Error: no CallbackHandler available to garner authentication information from the user");

			Callback[] callbacks = new Callback[2];
			callbacks[0] = new NameCallback("Username: ");
			callbacks[1] = new PasswordCallback("Password: ", false);

			try {
				callbackHandler.handle(callbacks);

				// Get username...
				username = ((NameCallback) callbacks[0]).getName();
				// ...password...
				password = ((PasswordCallback) callbacks[1]).getPassword();
				((PasswordCallback)callbacks[1]).clearPassword();
				
			} catch (java.io.IOException ioe) {
				throw new LoginException(ioe.toString());
			} catch (UnsupportedCallbackException uce) {
				throw new LoginException("Error: " + uce.getCallback().toString() +
						" not available to garner authentication information from the user");
			}

			// Attempt to logon using the supplied credentials
			principals = validateUser(username, new String(password) );     // may throw
		} finally {
			//Utils.smudge(password);
		}

		return true;
	}

		
	@Override
    public boolean commit() throws LoginException {
        subject.getPrincipals().addAll(principals);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        subject.getPrincipals().removeAll(principals);
        principals.clear();
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return false;
    }
	
    //
    protected abstract Set<Principal> validateUser(String username, String password) throws LoginException;
}
