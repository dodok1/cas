package org.apereo.cas.adaptors.radius.authentication;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apereo.cas.authentication.Credential;

import java.io.Serializable;

/**
 * This is {@link RadiusTokenCredential}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
public class RadiusTokenCredential implements Credential, Serializable {
    private static final long serialVersionUID = -7570675701132111037L;

    private String token;
    private Serializable state;
    private String message;

    @Override
    public String toString() {
        final ToStringBuilder builder = new ToStringBuilder(this)
                .append("token", this.token);
        if (state != null) builder.append(state);
        if (message != null) builder.append(message);
        return builder.toString();
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof RadiusTokenCredential)) {
            return false;
        }
        if (obj == this) {
            return true;
        }
        final RadiusTokenCredential other = (RadiusTokenCredential) obj;
        final EqualsBuilder builder = new EqualsBuilder();
        builder.append(this.token, other.token);
        return builder.isEquals();
    }

    @Override
    public int hashCode() {
        final HashCodeBuilder builder = new HashCodeBuilder(97, 31);
        builder.append(this.token);
        return builder.toHashCode();
    }

    @Override
    public String getId() {
        return this.token;
    }

    public String getToken() {
        return this.token;
    }

    public void setToken(final String token) {
        this.token = token;
    }

    public Serializable getState() {
        return state;
    }

    public void setState(Serializable state) {
        this.state = state;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isValid() {
        return StringUtils.isNotBlank(this.token);
    }
}

