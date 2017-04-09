package org.apereo.cas.adaptors.radius.web.flow;

import com.google.common.collect.ImmutableSet;
import org.apereo.cas.adaptors.radius.TokenChangeException;
import org.apereo.cas.adaptors.radius.authentication.RadiusTokenAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationException;
import org.apereo.cas.authentication.AuthenticationResultBuilder;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.web.flow.resolver.impl.AbstractCasWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import java.util.Set;

/**
 * This is {@link RadiusAuthenticationWebflowEventResolver}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */

public class RadiusAuthenticationWebflowEventResolver extends AbstractCasWebflowEventResolver {
    @Override
    protected Set<Event> resolveInternal(final RequestContext context) {
        try {
            final Credential credential = getCredentialFromContext(context);
            AuthenticationResultBuilder builder = WebUtils.getAuthenticationResultBuilder(context);

            logger.debug("Handling authentication transaction for credential {}", credential);
            builder = this.authenticationSystemSupport.handleAuthenticationTransaction(builder, credential);
            final Service service = WebUtils.getService(context);

            logger.debug("Issuing ticket-granting tickets for service {}", service);
            return ImmutableSet.of(grantTicketGrantingTicketToAuthenticationResult(context, builder, service));
        } catch (final AuthenticationException e) {
            Class<? extends Exception> error = e.getHandlerErrors().get(RadiusTokenAuthenticationHandler.class.getSimpleName());
            boolean tokenChange = error != null && error == TokenChangeException.class;
            context.getFlowScope().put("tokenChange", tokenChange);
            if (tokenChange) {
                return ImmutableSet.of(newEvent("tokenChange"));
            }
            else {
                return ImmutableSet.of(newEvent("error", e));
            }
        } catch (final Exception e) {
            return ImmutableSet.of(newEvent("error", e));
        }
    }

}
