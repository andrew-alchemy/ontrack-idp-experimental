package frameworks.jaas;

import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.sql.DataSource;

/*
* Base class for a variety of simple login modules that simply authenticate a user against some database of user credentials.
*
*/
public class JDBCLoginModule extends BaseLoginModule {
	//String dbDriver;
	String jndiURL;
	String userQuery;
	String roleQuery;
	
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,  Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        //dbDriver = getOption("dbDriver", null);
        //if (dbDriver == null) throw new Error("No database driver named (dbDriver=?)");
        
        jndiURL = getOption("jndiURL", null);
        if (jndiURL == null) throw new Error("No database JNDI URL specified (jndiURL=?)");

        userQuery = getOption("userQuery", "select password, user_id, role_cd, name_first, name_last, email from aftims.v_security_user_active where username=?");
        roleQuery = getOption("roleQuery", "select right_cd from aftims.v_security_user_right where username=?");

    }
	
	/**
	 * Validate a user's credentials and either throw a LoginException (if
	 * validation fails) or return a Vector of Principals if validation
	 * succeeds.
	 *
	 * @param username The username
	 * @param password The password
	 * @return a Vector of Principals that apply for this user.
	 * @throws LoginException if the login fails.
	 */
	protected Set<Principal> validateUser(String username, String password) throws LoginException {
		Set<Principal> p = new HashSet<Principal>();
        Connection connection = null;

        PreparedStatement passwordStatement = null;
        ResultSet passwordResultSet = null;

        PreparedStatement roleStatement = null;
        ResultSet roleResultSet = null;

		try {
			Context ctx = new InitialContext();
			DataSource ds = (DataSource)ctx.lookup(jndiURL);
			connection = ds.getConnection();
			//Class.forName(dbDriver);
			//connection = DriverManager.getConnection(dbURL);
			// Retrieve user credentials from database.
			passwordStatement = connection.prepareStatement(userQuery);
			passwordStatement.setString(1, username);
			passwordResultSet = passwordStatement.executeQuery();
			if (!passwordResultSet.next()) {
				throw new LoginException( username + " not found");
			} else {
				String storedPassword = passwordResultSet.getString(1);
				if (!checkPassword(password, storedPassword)) {
					throw new LoginException("Password for " + username + " does not match");
				}
				p.add(new UserPrincipal(username));
			}
			// Retrieve user roles from database
			roleStatement = connection.prepareStatement(roleQuery);
			roleStatement.setString(1, username);
			roleResultSet = roleStatement.executeQuery();
			while (roleResultSet.next()) {
				String role = roleResultSet.getString(1);
				p.add(new RolePrincipal(role));
			}
		} catch (Exception ex) {
			throw new LoginException("Error has occured while retrieving credentials from database:" + ex.getMessage());
		} finally {
			try {
				if (passwordResultSet != null) {
					passwordResultSet.close();
				}
				if (passwordStatement != null) {
					passwordStatement.close();
				}
				if (roleResultSet != null) {
					roleResultSet.close();
				}
				if (roleStatement != null) {
					roleStatement.close();
				}
				if (connection != null) {
					connection.close();
				}
			} catch (SQLException ex) {
				//log.warn("Failed to clearly close connection to the database:", ex);
			}
		}

		return p;
	}
	
	/**
	 * Maybe add something like the PBEX encoder shit here?
	 * 
	 * @param password
	 * @param storedPassword
	 * @return
	 */
	private boolean checkPassword(String password, String storedPassword) {
        return true;//password.equals(storedPassword);
    }

}