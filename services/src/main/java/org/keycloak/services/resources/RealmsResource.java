/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.services.resources;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.AuthorizationService;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.Profile;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.component.ComponentModel;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OTPPolicy;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.models.RequiredCredentialModel;
import org.keycloak.models.RoleModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.services.clientregistration.ClientRegistrationService;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.account.AccountLoader;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.services.util.ResolveRelative;
import org.keycloak.utils.MediaTypeMatcher;
import org.keycloak.utils.ProfileHelper;
import org.keycloak.wellknown.WellKnownProvider;

import javax.ws.rs.GET;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.OPTIONS;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Path("/realms")
public class RealmsResource {
    protected static final Logger logger = Logger.getLogger(RealmsResource.class);

    @Context
    protected KeycloakSession session;

    @Context
    protected ClientConnection clientConnection;

    @Context
    private HttpRequest request;

    public static UriBuilder realmBaseUrl(UriInfo uriInfo) {
        UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        return realmBaseUrl(baseUriBuilder);
    }

    public static UriBuilder realmBaseUrl(UriBuilder baseUriBuilder) {
        return baseUriBuilder.path(RealmsResource.class).path(RealmsResource.class, "getRealmResource");
    }

    public static UriBuilder accountUrl(UriBuilder base) {
        return base.path(RealmsResource.class).path(RealmsResource.class, "getAccountService");
    }

    public static UriBuilder protocolUrl(UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(RealmsResource.class, "getProtocol");
    }

    public static UriBuilder protocolUrl(UriBuilder builder) {
        return builder.path(RealmsResource.class).path(RealmsResource.class, "getProtocol");
    }

    public static UriBuilder clientRegistrationUrl(UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(RealmsResource.class, "getClientsService");
    }

    public static UriBuilder brokerUrl(UriInfo uriInfo) {
        return uriInfo.getBaseUriBuilder().path(RealmsResource.class).path(RealmsResource.class, "getBrokerService");
    }

    public static UriBuilder wellKnownProviderUrl(UriBuilder builder) {
        return builder.path(RealmsResource.class).path(RealmsResource.class, "getWellKnown");
    }

    @Path("{realm}/protocol/{protocol}")
    public Object getProtocol(final @PathParam("realm") String name,
                              final @PathParam("protocol") String protocol) {
        RealmModel realm = init(name);

        LoginProtocolFactory factory = (LoginProtocolFactory)session.getKeycloakSessionFactory().getProviderFactory(LoginProtocol.class, protocol);
        if(factory == null){
            logger.debugf("protocol %s not found", protocol);
            throw new NotFoundException("Protocol not found");
        }

        EventBuilder event = new EventBuilder(realm, session, clientConnection);

        Object endpoint = factory.createProtocolEndpoint(realm, event);

        ResteasyProviderFactory.getInstance().injectProperties(endpoint);
        return endpoint;
    }

    /**
     * Returns a temporary redirect to the client url configured for the given {@code clientId} in the given {@code realmName}.
     * <p>
     * This allows a client to refer to other clients just by their client id in URLs, will then redirect users to the actual client url.
     * The client url is derived according to the rules of the base url in the client configuration.
     * </p>
     *
     * @param realmName
     * @param clientId
     * @return
     * @since 2.0
     */
    @GET
    @Path("{realm}/clients/{client_id}/redirect")
    public Response getRedirect(final @PathParam("realm") String realmName, final @PathParam("client_id") String clientId) {

        RealmModel realm = init(realmName);

        if (realm == null) {
            return null;
        }

        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            return null;
        }

        if (client.getRootUrl() == null && client.getBaseUrl() == null) {
            return null;
        }


        URI targetUri;
        if (client.getRootUrl() != null && (client.getBaseUrl() == null || client.getBaseUrl().isEmpty())) {
            targetUri = KeycloakUriBuilder.fromUri(client.getRootUrl()).build();
        } else {
            targetUri = KeycloakUriBuilder.fromUri(ResolveRelative.resolveRelativeUri(session.getContext().getUri().getRequestUri(), client.getRootUrl(), client.getBaseUrl())).build();
        }

        return Response.seeOther(targetUri).build();
    }

    @Path("{realm}/login-actions")
    public LoginActionsService getLoginActionsService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        LoginActionsService service = new LoginActionsService(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(service);
        return service;
    }

    @Path("{realm}/clients-registrations")
    public ClientRegistrationService getClientsService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        ClientRegistrationService service = new ClientRegistrationService(event);
        ResteasyProviderFactory.getInstance().injectProperties(service);
        return service;
    }

    @Path("{realm}/clients-managements")
    public ClientsManagementService getClientsManagementService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        ClientsManagementService service = new ClientsManagementService(realm, event);
        ResteasyProviderFactory.getInstance().injectProperties(service);
        return service;
    }

    private RealmModel init(String realmName) {
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        if (realm == null) {
            throw new NotFoundException("Realm does not exist");
        }
        session.getContext().setRealm(realm);
        return realm;
    }

    @Path("{realm}/account")
    public Object getAccountService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        EventBuilder event = new EventBuilder(realm, session, clientConnection);
        return new AccountLoader().getAccountService(session, event);
    }

    @Path("{realm}")
    public PublicRealmResource getRealmResource(final @PathParam("realm") String name) {
        RealmModel realm = init(name);
        PublicRealmResource realmResource = new PublicRealmResource(realm);
        ResteasyProviderFactory.getInstance().injectProperties(realmResource);
        return realmResource;
    }

    @Path("{realm}/broker")
    public IdentityBrokerService getBrokerService(final @PathParam("realm") String name) {
        RealmModel realm = init(name);

        IdentityBrokerService brokerService = new IdentityBrokerService(realm);
        ResteasyProviderFactory.getInstance().injectProperties(brokerService);

        brokerService.init();

        return brokerService;
    }

    @OPTIONS
    @Path("{realm}/.well-known/{provider}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVersionPreflight(final @PathParam("realm") String name,
                                        final @PathParam("provider") String providerName) {
        return Cors.add(request, Response.ok()).allowedMethods("GET").preflight().auth().build();
    }

    @GET
    @Path("{realm}/.well-known/{provider}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getWellKnown(final @PathParam("realm") String name,
                                 final @PathParam("provider") String providerName) {
        try {
            init(name);
        }
        catch (NotFoundException e) {
            RealmModel fake = new RealmModel() {
                @Override
                public String getId() {
                    return name + "_not_exist";
                }

                @Override
                public String getName() {
                    return name + "_not_exist";
                }

                @Override
                public void setName(String name) {

                }

                @Override
                public String getDisplayName() {
                    return null;
                }

                @Override
                public void setDisplayName(String displayName) {

                }

                @Override
                public String getDisplayNameHtml() {
                    return null;
                }

                @Override
                public void setDisplayNameHtml(String displayNameHtml) {

                }

                @Override
                public boolean isEnabled() {
                    return false;
                }

                @Override
                public void setEnabled(boolean enabled) {

                }

                @Override
                public SslRequired getSslRequired() {
                    return null;
                }

                @Override
                public void setSslRequired(SslRequired sslRequired) {

                }

                @Override
                public boolean isRegistrationAllowed() {
                    return false;
                }

                @Override
                public void setRegistrationAllowed(boolean registrationAllowed) {

                }

                @Override
                public boolean isRegistrationEmailAsUsername() {
                    return false;
                }

                @Override
                public void setRegistrationEmailAsUsername(boolean registrationEmailAsUsername) {

                }

                @Override
                public boolean isRememberMe() {
                    return false;
                }

                @Override
                public void setRememberMe(boolean rememberMe) {

                }

                @Override
                public boolean isEditUsernameAllowed() {
                    return false;
                }

                @Override
                public void setEditUsernameAllowed(boolean editUsernameAllowed) {

                }

                @Override
                public boolean isUserManagedAccessAllowed() {
                    return false;
                }

                @Override
                public void setUserManagedAccessAllowed(boolean userManagedAccessAllowed) {

                }

                @Override
                public void setAttribute(String name, String value) {

                }

                @Override
                public void setAttribute(String name, Boolean value) {

                }

                @Override
                public void setAttribute(String name, Integer value) {

                }

                @Override
                public void setAttribute(String name, Long value) {

                }

                @Override
                public void removeAttribute(String name) {

                }

                @Override
                public String getAttribute(String name) {
                    return null;
                }

                @Override
                public Integer getAttribute(String name, Integer defaultValue) {
                    return null;
                }

                @Override
                public Long getAttribute(String name, Long defaultValue) {
                    return null;
                }

                @Override
                public Boolean getAttribute(String name, Boolean defaultValue) {
                    return null;
                }

                @Override
                public Map<String, String> getAttributes() {
                    return null;
                }

                @Override
                public boolean isBruteForceProtected() {
                    return false;
                }

                @Override
                public void setBruteForceProtected(boolean value) {

                }

                @Override
                public boolean isPermanentLockout() {
                    return false;
                }

                @Override
                public void setPermanentLockout(boolean val) {

                }

                @Override
                public int getMaxFailureWaitSeconds() {
                    return 0;
                }

                @Override
                public void setMaxFailureWaitSeconds(int val) {

                }

                @Override
                public int getWaitIncrementSeconds() {
                    return 0;
                }

                @Override
                public void setWaitIncrementSeconds(int val) {

                }

                @Override
                public int getMinimumQuickLoginWaitSeconds() {
                    return 0;
                }

                @Override
                public void setMinimumQuickLoginWaitSeconds(int val) {

                }

                @Override
                public long getQuickLoginCheckMilliSeconds() {
                    return 0;
                }

                @Override
                public void setQuickLoginCheckMilliSeconds(long val) {

                }

                @Override
                public int getMaxDeltaTimeSeconds() {
                    return 0;
                }

                @Override
                public void setMaxDeltaTimeSeconds(int val) {

                }

                @Override
                public int getFailureFactor() {
                    return 0;
                }

                @Override
                public void setFailureFactor(int failureFactor) {

                }

                @Override
                public boolean isVerifyEmail() {
                    return false;
                }

                @Override
                public void setVerifyEmail(boolean verifyEmail) {

                }

                @Override
                public boolean isLoginWithEmailAllowed() {
                    return false;
                }

                @Override
                public void setLoginWithEmailAllowed(boolean loginWithEmailAllowed) {

                }

                @Override
                public boolean isDuplicateEmailsAllowed() {
                    return false;
                }

                @Override
                public void setDuplicateEmailsAllowed(boolean duplicateEmailsAllowed) {

                }

                @Override
                public boolean isResetPasswordAllowed() {
                    return false;
                }

                @Override
                public void setResetPasswordAllowed(boolean resetPasswordAllowed) {

                }

                @Override
                public String getDefaultSignatureAlgorithm() {
                    return null;
                }

                @Override
                public void setDefaultSignatureAlgorithm(String defaultSignatureAlgorithm) {

                }

                @Override
                public boolean isRevokeRefreshToken() {
                    return false;
                }

                @Override
                public void setRevokeRefreshToken(boolean revokeRefreshToken) {

                }

                @Override
                public int getRefreshTokenMaxReuse() {
                    return 0;
                }

                @Override
                public void setRefreshTokenMaxReuse(int revokeRefreshTokenCount) {

                }

                @Override
                public int getSsoSessionIdleTimeout() {
                    return 0;
                }

                @Override
                public void setSsoSessionIdleTimeout(int seconds) {

                }

                @Override
                public int getSsoSessionMaxLifespan() {
                    return 0;
                }

                @Override
                public void setSsoSessionMaxLifespan(int seconds) {

                }

                @Override
                public int getSsoSessionIdleTimeoutRememberMe() {
                    return 0;
                }

                @Override
                public void setSsoSessionIdleTimeoutRememberMe(int seconds) {

                }

                @Override
                public int getSsoSessionMaxLifespanRememberMe() {
                    return 0;
                }

                @Override
                public void setSsoSessionMaxLifespanRememberMe(int seconds) {

                }

                @Override
                public int getOfflineSessionIdleTimeout() {
                    return 0;
                }

                @Override
                public void setOfflineSessionIdleTimeout(int seconds) {

                }

                @Override
                public int getAccessTokenLifespan() {
                    return 0;
                }

                @Override
                public boolean isOfflineSessionMaxLifespanEnabled() {
                    return false;
                }

                @Override
                public void setOfflineSessionMaxLifespanEnabled(boolean offlineSessionMaxLifespanEnabled) {

                }

                @Override
                public int getOfflineSessionMaxLifespan() {
                    return 0;
                }

                @Override
                public void setOfflineSessionMaxLifespan(int seconds) {

                }

                @Override
                public void setAccessTokenLifespan(int seconds) {

                }

                @Override
                public int getAccessTokenLifespanForImplicitFlow() {
                    return 0;
                }

                @Override
                public void setAccessTokenLifespanForImplicitFlow(int seconds) {

                }

                @Override
                public int getAccessCodeLifespan() {
                    return 0;
                }

                @Override
                public void setAccessCodeLifespan(int seconds) {

                }

                @Override
                public int getAccessCodeLifespanUserAction() {
                    return 0;
                }

                @Override
                public void setAccessCodeLifespanUserAction(int seconds) {

                }

                @Override
                public Map<String, Integer> getUserActionTokenLifespans() {
                    return null;
                }

                @Override
                public int getAccessCodeLifespanLogin() {
                    return 0;
                }

                @Override
                public void setAccessCodeLifespanLogin(int seconds) {

                }

                @Override
                public int getActionTokenGeneratedByAdminLifespan() {
                    return 0;
                }

                @Override
                public void setActionTokenGeneratedByAdminLifespan(int seconds) {

                }

                @Override
                public int getActionTokenGeneratedByUserLifespan() {
                    return 0;
                }

                @Override
                public void setActionTokenGeneratedByUserLifespan(int seconds) {

                }

                @Override
                public int getActionTokenGeneratedByUserLifespan(String actionTokenType) {
                    return 0;
                }

                @Override
                public void setActionTokenGeneratedByUserLifespan(String actionTokenType, Integer seconds) {

                }

                @Override
                public List<RequiredCredentialModel> getRequiredCredentials() {
                    return null;
                }

                @Override
                public void addRequiredCredential(String cred) {

                }

                @Override
                public PasswordPolicy getPasswordPolicy() {
                    return null;
                }

                @Override
                public void setPasswordPolicy(PasswordPolicy policy) {

                }

                @Override
                public OTPPolicy getOTPPolicy() {
                    return null;
                }

                @Override
                public void setOTPPolicy(OTPPolicy policy) {

                }

                @Override
                public RoleModel getRoleById(String id) {
                    return null;
                }

                @Override
                public List<GroupModel> getDefaultGroups() {
                    return null;
                }

                @Override
                public void addDefaultGroup(GroupModel group) {

                }

                @Override
                public void removeDefaultGroup(GroupModel group) {

                }

                @Override
                public List<ClientModel> getClients() {
                    return null;
                }

                @Override
                public ClientModel addClient(String name) {
                    return null;
                }

                @Override
                public ClientModel addClient(String id, String clientId) {
                    return null;
                }

                @Override
                public boolean removeClient(String id) {
                    return false;
                }

                @Override
                public ClientModel getClientById(String id) {
                    return null;
                }

                @Override
                public ClientModel getClientByClientId(String clientId) {
                    return null;
                }

                @Override
                public void updateRequiredCredentials(Set<String> creds) {

                }

                @Override
                public Map<String, String> getBrowserSecurityHeaders() {
                    return null;
                }

                @Override
                public void setBrowserSecurityHeaders(Map<String, String> headers) {

                }

                @Override
                public Map<String, String> getSmtpConfig() {
                    return null;
                }

                @Override
                public void setSmtpConfig(Map<String, String> smtpConfig) {

                }

                @Override
                public AuthenticationFlowModel getBrowserFlow() {
                    return null;
                }

                @Override
                public void setBrowserFlow(AuthenticationFlowModel flow) {

                }

                @Override
                public AuthenticationFlowModel getRegistrationFlow() {
                    return null;
                }

                @Override
                public void setRegistrationFlow(AuthenticationFlowModel flow) {

                }

                @Override
                public AuthenticationFlowModel getDirectGrantFlow() {
                    return null;
                }

                @Override
                public void setDirectGrantFlow(AuthenticationFlowModel flow) {

                }

                @Override
                public AuthenticationFlowModel getResetCredentialsFlow() {
                    return null;
                }

                @Override
                public void setResetCredentialsFlow(AuthenticationFlowModel flow) {

                }

                @Override
                public AuthenticationFlowModel getClientAuthenticationFlow() {
                    return null;
                }

                @Override
                public void setClientAuthenticationFlow(AuthenticationFlowModel flow) {

                }

                @Override
                public AuthenticationFlowModel getDockerAuthenticationFlow() {
                    return null;
                }

                @Override
                public void setDockerAuthenticationFlow(AuthenticationFlowModel flow) {

                }

                @Override
                public List<AuthenticationFlowModel> getAuthenticationFlows() {
                    return null;
                }

                @Override
                public AuthenticationFlowModel getFlowByAlias(String alias) {
                    return null;
                }

                @Override
                public AuthenticationFlowModel addAuthenticationFlow(AuthenticationFlowModel model) {
                    return null;
                }

                @Override
                public AuthenticationFlowModel getAuthenticationFlowById(String id) {
                    return null;
                }

                @Override
                public void removeAuthenticationFlow(AuthenticationFlowModel model) {

                }

                @Override
                public void updateAuthenticationFlow(AuthenticationFlowModel model) {

                }

                @Override
                public List<AuthenticationExecutionModel> getAuthenticationExecutions(String flowId) {
                    return null;
                }

                @Override
                public AuthenticationExecutionModel getAuthenticationExecutionById(String id) {
                    return null;
                }

                @Override
                public AuthenticationExecutionModel addAuthenticatorExecution(AuthenticationExecutionModel model) {
                    return null;
                }

                @Override
                public void updateAuthenticatorExecution(AuthenticationExecutionModel model) {

                }

                @Override
                public void removeAuthenticatorExecution(AuthenticationExecutionModel model) {

                }

                @Override
                public List<AuthenticatorConfigModel> getAuthenticatorConfigs() {
                    return null;
                }

                @Override
                public AuthenticatorConfigModel addAuthenticatorConfig(AuthenticatorConfigModel model) {
                    return null;
                }

                @Override
                public void updateAuthenticatorConfig(AuthenticatorConfigModel model) {

                }

                @Override
                public void removeAuthenticatorConfig(AuthenticatorConfigModel model) {

                }

                @Override
                public AuthenticatorConfigModel getAuthenticatorConfigById(String id) {
                    return null;
                }

                @Override
                public AuthenticatorConfigModel getAuthenticatorConfigByAlias(String alias) {
                    return null;
                }

                @Override
                public List<RequiredActionProviderModel> getRequiredActionProviders() {
                    return null;
                }

                @Override
                public RequiredActionProviderModel addRequiredActionProvider(RequiredActionProviderModel model) {
                    return null;
                }

                @Override
                public void updateRequiredActionProvider(RequiredActionProviderModel model) {

                }

                @Override
                public void removeRequiredActionProvider(RequiredActionProviderModel model) {

                }

                @Override
                public RequiredActionProviderModel getRequiredActionProviderById(String id) {
                    return null;
                }

                @Override
                public RequiredActionProviderModel getRequiredActionProviderByAlias(String alias) {
                    return null;
                }

                @Override
                public List<IdentityProviderModel> getIdentityProviders() {
                    return null;
                }

                @Override
                public IdentityProviderModel getIdentityProviderByAlias(String alias) {
                    return null;
                }

                @Override
                public void addIdentityProvider(IdentityProviderModel identityProvider) {

                }

                @Override
                public void removeIdentityProviderByAlias(String alias) {

                }

                @Override
                public void updateIdentityProvider(IdentityProviderModel identityProvider) {

                }

                @Override
                public Set<IdentityProviderMapperModel> getIdentityProviderMappers() {
                    return null;
                }

                @Override
                public Set<IdentityProviderMapperModel> getIdentityProviderMappersByAlias(String brokerAlias) {
                    return null;
                }

                @Override
                public IdentityProviderMapperModel addIdentityProviderMapper(IdentityProviderMapperModel model) {
                    return null;
                }

                @Override
                public void removeIdentityProviderMapper(IdentityProviderMapperModel mapping) {

                }

                @Override
                public void updateIdentityProviderMapper(IdentityProviderMapperModel mapping) {

                }

                @Override
                public IdentityProviderMapperModel getIdentityProviderMapperById(String id) {
                    return null;
                }

                @Override
                public IdentityProviderMapperModel getIdentityProviderMapperByName(String brokerAlias, String name) {
                    return null;
                }

                @Override
                public ComponentModel addComponentModel(ComponentModel model) {
                    return null;
                }

                @Override
                public ComponentModel importComponentModel(ComponentModel model) {
                    return null;
                }

                @Override
                public void updateComponent(ComponentModel component) {

                }

                @Override
                public void removeComponent(ComponentModel component) {

                }

                @Override
                public void removeComponents(String parentId) {

                }

                @Override
                public List<ComponentModel> getComponents(String parentId, String providerType) {
                    return null;
                }

                @Override
                public List<ComponentModel> getComponents(String parentId) {
                    return null;
                }

                @Override
                public List<ComponentModel> getComponents() {
                    return null;
                }

                @Override
                public ComponentModel getComponent(String id) {
                    return null;
                }

                @Override
                public String getLoginTheme() {
                    return null;
                }

                @Override
                public void setLoginTheme(String name) {

                }

                @Override
                public String getAccountTheme() {
                    return null;
                }

                @Override
                public void setAccountTheme(String name) {

                }

                @Override
                public String getAdminTheme() {
                    return null;
                }

                @Override
                public void setAdminTheme(String name) {

                }

                @Override
                public String getEmailTheme() {
                    return null;
                }

                @Override
                public void setEmailTheme(String name) {

                }

                @Override
                public int getNotBefore() {
                    return 0;
                }

                @Override
                public void setNotBefore(int notBefore) {

                }

                @Override
                public boolean isEventsEnabled() {
                    return false;
                }

                @Override
                public void setEventsEnabled(boolean enabled) {

                }

                @Override
                public long getEventsExpiration() {
                    return 0;
                }

                @Override
                public void setEventsExpiration(long expiration) {

                }

                @Override
                public Set<String> getEventsListeners() {
                    return null;
                }

                @Override
                public void setEventsListeners(Set<String> listeners) {

                }

                @Override
                public Set<String> getEnabledEventTypes() {
                    return null;
                }

                @Override
                public void setEnabledEventTypes(Set<String> enabledEventTypes) {

                }

                @Override
                public boolean isAdminEventsEnabled() {
                    return false;
                }

                @Override
                public void setAdminEventsEnabled(boolean enabled) {

                }

                @Override
                public boolean isAdminEventsDetailsEnabled() {
                    return false;
                }

                @Override
                public void setAdminEventsDetailsEnabled(boolean enabled) {

                }

                @Override
                public ClientModel getMasterAdminClient() {
                    return null;
                }

                @Override
                public void setMasterAdminClient(ClientModel client) {

                }

                @Override
                public boolean isIdentityFederationEnabled() {
                    return false;
                }

                @Override
                public boolean isInternationalizationEnabled() {
                    return false;
                }

                @Override
                public void setInternationalizationEnabled(boolean enabled) {

                }

                @Override
                public Set<String> getSupportedLocales() {
                    return null;
                }

                @Override
                public void setSupportedLocales(Set<String> locales) {

                }

                @Override
                public String getDefaultLocale() {
                    return null;
                }

                @Override
                public void setDefaultLocale(String locale) {

                }

                @Override
                public GroupModel createGroup(String name) {
                    return null;
                }

                @Override
                public GroupModel createGroup(String id, String name) {
                    return null;
                }

                @Override
                public GroupModel getGroupById(String id) {
                    return null;
                }

                @Override
                public List<GroupModel> getGroups() {
                    return null;
                }

                @Override
                public Long getGroupsCount(Boolean onlyTopGroups) {
                    return null;
                }

                @Override
                public Long getGroupsCountByNameContaining(String search) {
                    return null;
                }

                @Override
                public List<GroupModel> getTopLevelGroups() {
                    return null;
                }

                @Override
                public List<GroupModel> getTopLevelGroups(Integer first, Integer max) {
                    return null;
                }

                @Override
                public List<GroupModel> searchForGroupByName(String search, Integer first, Integer max) {
                    return null;
                }

                @Override
                public boolean removeGroup(GroupModel group) {
                    return false;
                }

                @Override
                public void moveGroup(GroupModel group, GroupModel toParent) {

                }

                @Override
                public List<ClientScopeModel> getClientScopes() {
                    return Collections.emptyList();
                }

                @Override
                public ClientScopeModel addClientScope(String name) {
                    return null;
                }

                @Override
                public ClientScopeModel addClientScope(String id, String name) {
                    return null;
                }

                @Override
                public boolean removeClientScope(String id) {
                    return false;
                }

                @Override
                public ClientScopeModel getClientScopeById(String id) {
                    return null;
                }

                @Override
                public void addDefaultClientScope(ClientScopeModel clientScope, boolean defaultScope) {

                }

                @Override
                public void removeDefaultClientScope(ClientScopeModel clientScope) {

                }

                @Override
                public List<ClientScopeModel> getDefaultClientScopes(boolean defaultScope) {
                    return null;
                }

                @Override
                public RoleModel getRole(String name) {
                    return null;
                }

                @Override
                public RoleModel addRole(String name) {
                    return null;
                }

                @Override
                public RoleModel addRole(String id, String name) {
                    return null;
                }

                @Override
                public boolean removeRole(RoleModel role) {
                    return false;
                }

                @Override
                public Set<RoleModel> getRoles() {
                    return null;
                }

                @Override
                public List<String> getDefaultRoles() {
                    return null;
                }

                @Override
                public void addDefaultRole(String name) {

                }

                @Override
                public void updateDefaultRoles(String... defaultRoles) {

                }

                @Override
                public void removeDefaultRoles(String... defaultRoles) {

                }
            };
            session.getContext().setRealm(fake);
        }

        WellKnownProvider wellKnown = session.getProvider(WellKnownProvider.class, providerName);
        if (wellKnown != null) {
            ResponseBuilder responseBuilder = Response.ok(wellKnown.getConfig()).cacheControl(CacheControlUtil.noCache());
            return Cors.add(request, responseBuilder).allowedOrigins("*").auth().build();
        }
        throw new NotFoundException();
    }

    @Path("{realm}/authz")
    public Object getAuthorizationService(@PathParam("realm") String name) {
        init(name);
        AuthorizationProvider authorization = this.session.getProvider(AuthorizationProvider.class);
        AuthorizationService service = new AuthorizationService(authorization);

        ResteasyProviderFactory.getInstance().injectProperties(service);

        return service;
    }

    /**
     * A JAX-RS sub-resource locator that uses the {@link org.keycloak.services.resource.RealmResourceSPI} to resolve sub-resources instances given an <code>unknownPath</code>.
     *
     * @param extension a path that could be to a REST extension
     * @return a JAX-RS sub-resource instance for the REST extension if found. Otherwise null is returned.
     */
    @Path("{realm}/{extension}")
    public Object resolveRealmExtension(@PathParam("realm") String realmName, @PathParam("extension") String extension) {
        RealmResourceProvider provider = session.getProvider(RealmResourceProvider.class, extension);
        if (provider != null) {
            init(realmName);
            Object resource = provider.getResource();
            if (resource != null) {
                return resource;
            }
        }

        throw new NotFoundException();
    }
}
