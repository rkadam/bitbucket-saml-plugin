package com.pandora.bitbucket.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class BitbucketSAMLRedirectServlet extends HttpServlet{
    private static final Logger log = LoggerFactory.getLogger(BitbucketSAMLRedirectServlet.class);
    private static final String KEY_CONTAINER_AUTH_NAME = "auth.container.remote-user";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        doPost(request, response);

    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException
    {
        // this page is where SAML authentication returns as POST submission to this Servlet.
        // if auth is successful, user is already added to session via BitbucketSAMLHandler and
        // we redirect to the url stored in RelayState.
        // Otherwise, we display an error page.
        log.debug("BitbucketSAMLRedirectServlet - doGet(): Returning from SAML Authentication.");

        //final JiraAuthenticationContext jiraAuthenticationContext = ComponentManager.getComponentInstanceOfType(JiraAuthenticationContext.class);
        //if (jiraAuthenticationContext.getLoggedInUser() != null) {

        // verify SAMLResponse
        // How to verify if BitBucket has this user loggedIn or not, the way jiraAuthenticationContext is being useful for JIRA.
        // Right now we will use session attribute that we set in authHandler. But need to find if there is any better way to get this done.
        HttpSession session = request.getSession(false);
        if ((session != null) && session.getAttribute(KEY_CONTAINER_AUTH_NAME) != null) {

            log.debug("Valid BitBucket User. We will redirect user to right place.");

            // great, go back to wherever we started.
            //request.setAttribute("loggedInUser", jiraAuthenticationContext.getLoggedInUser() == null ? null : jiraAuthenticationContext.getLoggedInUser().getDisplayName());
            String originalUrl = request.getParameter("RelayState");
            if (originalUrl == null)
                originalUrl = "/";

            response.sendRedirect(response.encodeRedirectURL(originalUrl));
        } else {
            // SAML login failed.
            // TODO: Find out how to pass error within Bitbucket application container like their 500 error page or so.
            log.error("SAML Login failed. Unable to validate your account.");
            response.setContentType("text/html");
            response.getWriter().write("<html><body>Sorry, we were unable to validate your account.</body></html>");
        }
    }

}