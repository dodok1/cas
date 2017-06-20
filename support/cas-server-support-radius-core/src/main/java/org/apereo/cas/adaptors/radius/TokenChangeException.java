package org.apereo.cas.adaptors.radius;

import javax.security.auth.login.LoginException;

/**
 * Exception indicating that provided login credentials are not complete and should provided again with changed token.
 */
public class TokenChangeException extends LoginException {

    private static final long serialVersionUID = 0;

    /**
     * Constructs a {@link TokenChangeException} with the specified detail message.
     * A detail message is a String that describes change required from authentication backend.
     *
     * <p>
     *
     * @param msg instruction for complete authentication.
     */
    public TokenChangeException(String msg) {
        super(msg);
    }
}
