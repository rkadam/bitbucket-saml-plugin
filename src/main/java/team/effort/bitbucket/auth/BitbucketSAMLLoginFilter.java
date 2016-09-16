package com.pandora.bitbucket.auth;

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

import com.pandora.bitbucket.auth.BitbucketSAMLHandler;

public class BitbucketSAMLLoginFilter implements Filter {

    private final I18nService i18nService;
    private final UserService userService;
    private static final Logger log = LoggerFactory.getLogger(BitbucketSAMLLoginFilter.class);

    public BitbucketSAMLLoginFilter(I18nService i18nService, UserService userService){
        this.i18nService = i18nService;
        this.userService = userService;
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
                String url = new BitbucketSAMLHandler(i18nService, userService).getRedirectUrl(request.getParameter("os_destination"));
                log.debug("saml_login: redirecting user to " + url);
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