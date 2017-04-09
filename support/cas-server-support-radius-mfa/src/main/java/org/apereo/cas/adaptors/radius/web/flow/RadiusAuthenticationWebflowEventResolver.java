package org.apereo.cas.adaptors.radius.web.flow;

import com.google.common.collect.ImmutableSet;
import org.apereo.cas.CentralAuthenticationService;
import org.apereo.cas.adaptors.radius.TokenChangeException;
import org.apereo.cas.adaptors.radius.authentication.RadiusTokenAuthenticationHandler;
import org.apereo.cas.authentication.*;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.services.MultifactorAuthenticationProviderSelector;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.ticket.registry.TicketRegistrySupport;
import org.apereo.cas.web.flow.resolver.impl.AbstractCasWebflowEventResolver;
import org.apereo.cas.web.support.WebUtils;
import org.apereo.inspektr.audit.annotation.Audit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.util.CookieGenerator;
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

    private static final Logger LOGGER = LoggerFactory.getLogger(RadiusTokenAuthenticationHandler.class);

    public RadiusAuthenticationWebflowEventResolver(final AuthenticationSystemSupport authenticationSystemSupport,
                                                    final CentralAuthenticationService centralAuthenticationService, 
                                                    final ServicesManager servicesManager,
                                                    final TicketRegistrySupport ticketRegistrySupport, 
                                                    final CookieGenerator warnCookieGenerator,
                                                    final AuthenticationServiceSelectionPlan authenticationSelectionStrategies,
                                                    final MultifactorAuthenticationProviderSelector selector) {
        super(authenticationSystemSupport, centralAuthenticationService, 
                servicesManager, ticketRegistrySupport, warnCookieGenerator,
                authenticationSelectionStrategies, selector);
    }

    @Override
    public Set<Event> resolveInternal(final RequestContext context) {
        try {
            final Credential credential = getCredentialFromContext(context);
            AuthenticationResultBuilder builder = WebUtils.getAuthenticationResultBuilder(context);

            LOGGER.debug("Handling authentication transaction for credential {}", credential);
            final Service service = WebUtils.getService(context);
            builder = this.authenticationSystemSupport.handleAuthenticationTransaction(service, builder, credential);

            LOGGER.debug("Issuing ticket-granting tickets for service {}", service);
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

    @Audit(action = "AUTHENTICATION_EVENT", actionResolverName = "AUTHENTICATION_EVENT_ACTION_RESOLVER",
            resourceResolverName = "AUTHENTICATION_EVENT_RESOURCE_RESOLVER")
    @Override
    public Event resolveSingle(final RequestContext context) {
        return super.resolveSingle(context);
    }
}
