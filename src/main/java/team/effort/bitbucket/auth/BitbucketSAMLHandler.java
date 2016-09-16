package com.pandora.bitbucket.auth;

import com.lastpass.saml.SAMLInit;
import com.lastpass.saml.SAMLClient;
import com.lastpass.saml.SAMLException;
import com.lastpass.saml.SAMLUtils;
import com.lastpass.saml.IdPConfig;
import com.lastpass.saml.SPConfig;
import com.lastpass.saml.AttributeSet;

import java.security.Principal;
import java.security.SecureRandom;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.ArrayList;
import java.net.URLEncoder;

import com.atlassian.bitbucket.auth.*;
import com.atlassian.bitbucket.i18n.I18nService;
import com.atlassian.bitbucket.user.ApplicationUser;
import com.atlassian.bitbucket.user.UserService;
import com.google.common.base.Objects;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class BitbucketSAMLHandler implements HttpAuthenticationHandler, HttpAuthenticationSuccessHandler {

    private SAMLClient client;
    private static final String KEY_CONTAINER_AUTH_NAME = "auth.container.remote-user";
    private static final Logger log = LoggerFactory.getLogger(BitbucketSAMLHandler.class);

    private final I18nService i18nService;
    private final UserService userService;

    public BitbucketSAMLHandler(I18nService i18nService, UserService userService) throws SAMLException {
        this.i18nService = i18nService;
        this.userService = userService;

        SAMLInit.initialize();

        String dir = findMetadataDir();
        if (dir == null) {
            throw new SAMLException("Unable to locate SAML metadata");
        }

        IdPConfig idpConfig = new IdPConfig(new File(dir + "/idp-metadata.xml"));
        SPConfig spConfig = new SPConfig(new File(dir + "/sp-metadata.xml"));
        log.debug("Loading BitbucketSAMLHandler...");

        client = new SAMLClient(spConfig, idpConfig);
    }

    /**
     * Look for the directory that contains *-metadata.xml.
     * <p>
     * We look in the catalina.base directory first, then make some
     * wild guesses.
     */
    private String findMetadataDir() {
        String[] dirs = {
                System.getProperty("catalina.base", "."),
                ".",
                "..",
        };
        List<String> attempted = new ArrayList<String>();

        for (String dir : dirs) {
            File path = new File(dir + "/idp-metadata.xml");
            attempted.add(path.getAbsolutePath());
            if (path.exists())
                return dir;
        }

        //No Luck in finding idp-metadata.xml
        log.error("Unable to locate SAML metadata, tried " + attempted);
        return null;
    }

    public String getRedirectUrl(String relayState) {
        String requestId = SAMLUtils.generateRequestId();
        try {
            String authrequest = client.generateAuthnRequest(requestId);
            String url = client.getIdPConfig().getLoginUrl();
            url = url +
                    "?SAMLRequest=" + URLEncoder.encode(authrequest, "UTF-8");

            if (relayState != null)
                url += "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");

            return url;
        } catch (SAMLException e) {
            log.error("Could not generate AuthnRequest", e);
        } catch (UnsupportedEncodingException e) {
            log.error("Missing UTF-8 support", e);
        }
        return null;
    }


    @Nullable
    @Override
    public ApplicationUser authenticate(@Nonnull HttpAuthenticationContext httpAuthenticationContext) {
        log.debug("authenticate() for BitbucketSAMLHandler. start...");

        HttpServletRequest request = httpAuthenticationContext.getRequest();
        HttpSession session = httpAuthenticationContext.getRequest().getSession(false);
        if ((session != null) && session.getAttribute(KEY_CONTAINER_AUTH_NAME) != null) {
            log.debug("authenticate() - valid session");
            String authenticatedUserId = (String) session.getAttribute(KEY_CONTAINER_AUTH_NAME);
            log.debug("authenticate() - user = " + authenticatedUserId);
            ApplicationUser user = userService.getUserByName(authenticatedUserId);
            if (user != null) {
                log.debug("authenticate() - valid application user. Returning with this user.");
                return user;
            }
        }

        if (request.getParameter("SAMLResponse") == null) {
            // we don't have a user, nor a saml token to look at.
            // return null, so caller will redirect to saml login
            // page.
            log.error("NULL SAMLResponse. Redirect caller to SAML login page.");
            return null;
        }

        // Consume and validate the assertions in the response.
        String authresponse = request.getParameter("SAMLResponse");
        AttributeSet aset;
        try {
            aset = client.validateResponse(authresponse);
        } catch (SAMLException e) {
            // response invalid.
            log.error("SAML response invalid", e);
            return null;
        }

        String username = aset.getNameId();
        log.debug("SAML user: " + username);

        ApplicationUser user = userService.getUserByName(username);
        if (user == null) {
            // we are not be creating user now. Log error and return null.
            // TODO: Phase 2, should be configurable from Admin Interface if user creation is allowed or not.
            log.error("User " + username + " not found. Please find out why this user is not associated to application.");
            return null;
        }

        request.setAttribute(KEY_CONTAINER_AUTH_NAME, username);
        log.debug("authenticate() for BitbucketSAMLHandler. end...");
        return user;
    }

    @Override
    public void validateAuthentication(@Nonnull HttpAuthenticationContext httpAuthenticationContext) {
        log.debug("validateAuthentication() - start...");
        HttpSession session = httpAuthenticationContext.getRequest().getSession(false);
        if (session == null) {
            // nothing to validate - the user wasn't authenticated by this authentication handler
            log.debug("No session present. User is not authenticated by this auth handler...");
            return;
        }

        String sessionUser = (String) session.getAttribute(KEY_CONTAINER_AUTH_NAME);
        String remoteUser = httpAuthenticationContext.getRequest().getRemoteUser();
        log.debug("validateAuthentication() - sessionUser - " + sessionUser + " remoteUser - " + remoteUser);
        if (sessionUser != null && !Objects.equal(sessionUser, remoteUser)) {
            throw new ExpiredAuthenticationException(i18nService.getKeyedText("container.auth.usernamenomatch",
                    "Session username '{0}' does not match username provided by the container '{1}'",
                    sessionUser, remoteUser));
        }
        log.debug("validateAuthentication() - end");
    }

    @Override
    public boolean onAuthenticationSuccess(@Nonnull HttpAuthenticationSuccessContext context) throws ServletException, IOException {
        // if this authentication handler was responsible for the authentication, an attribute has been stored on the
        // request. If that's the case, persist it in the session so it can be used in future authentication validations

        log.debug("onAuthenticationSuccess() - start...");
        String authenticationUser = (String) context.getRequest().getAttribute(KEY_CONTAINER_AUTH_NAME);
        log.debug("onAuthenticationSuccess() - authenticationUser - " + authenticationUser);
        if (authenticationUser != null) {
            log.debug("onAuthenticationSuccess() - setting session attribute");
            context.getRequest().getSession().setAttribute(KEY_CONTAINER_AUTH_NAME, authenticationUser);
        }

        log.debug("onAuthenticationSuccess() - end.");

        //Returning 'false' helps to pass control to other success handlers further down the chain!
        return false;
    }
}