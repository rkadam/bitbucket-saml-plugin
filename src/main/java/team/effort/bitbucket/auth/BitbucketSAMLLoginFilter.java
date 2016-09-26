package team.effort.bitbucket.auth;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.atlassian.bitbucket.i18n.I18nService;
import com.atlassian.bitbucket.user.UserService;
import com.atlassian.bitbucket.auth.AuthenticationContext;

import team.effort.bitbucket.auth.BitbucketSAMLHandler;

public class BitbucketSAMLLoginFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(BitbucketSAMLLoginFilter.class);

    private final I18nService i18nService;
    private final UserService userService;
    private final AuthenticationContext bitbucketAuthenticationContext;


    public BitbucketSAMLLoginFilter(I18nService i18nService,
                                    UserService userService,
                                    AuthenticationContext bitbucketAuthenticationContext ){
        this.i18nService = i18nService;
        this.userService = userService;
        this.bitbucketAuthenticationContext = bitbucketAuthenticationContext;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        boolean idpRequired = true;

        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        if (idpRequired == true) {
            try {
                String url = new BitbucketSAMLHandler(i18nService, userService, bitbucketAuthenticationContext).getRedirectUrl(request.getParameter("next"));
                log.debug("saml_login -> User trying to access URL - " + url);
                res.sendRedirect(res.encodeRedirectURL(url));
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {
    }
}