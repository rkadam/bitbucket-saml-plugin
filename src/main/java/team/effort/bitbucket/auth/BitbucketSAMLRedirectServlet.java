package team.effort.bitbucket.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import com.atlassian.bitbucket.auth.AuthenticationContext;
import com.atlassian.bitbucket.user.ApplicationUser;

public class BitbucketSAMLRedirectServlet extends HttpServlet{
    private static final Logger log = LoggerFactory.getLogger(BitbucketSAMLRedirectServlet.class);

    private final AuthenticationContext bitbucketAuthenticationContext;

    public BitbucketSAMLRedirectServlet( AuthenticationContext bitbucketAuthenticationContext){
        this.bitbucketAuthenticationContext = bitbucketAuthenticationContext;
    }

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

        // verify SAMLResponse
        boolean isUserAuthenticated = bitbucketAuthenticationContext.isAuthenticated();
        ApplicationUser authenticatedUser = bitbucketAuthenticationContext.getCurrentUser();

        if (isUserAuthenticated && (authenticatedUser != null) ) {

            log.debug("Valid BitBucket User. We will redirect user to right place.");

            // great, go back to wherever we started.
            String originalUrl = request.getParameter("RelayState");
            log.debug("Original URL from RelayState - " + originalUrl);
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