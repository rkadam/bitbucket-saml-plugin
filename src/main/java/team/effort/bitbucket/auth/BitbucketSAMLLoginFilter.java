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

import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.atlassian.bitbucket.i18n.I18nService;
import com.atlassian.bitbucket.user.UserService;
import com.atlassian.bitbucket.auth.AuthenticationContext;

import team.effort.bitbucket.auth.BitbucketSAMLHandler;
import team.effort.bitbucket.config.BitbucketSAMLAdminConfigResource;

import static team.effort.bitbucket.config.BitbucketSAMLAdminServlet.PLUGIN_STORAGE_KEY;

public class BitbucketSAMLLoginFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(BitbucketSAMLLoginFilter.class);

    private final I18nService i18nService;
    private final UserService userService;
    private final AuthenticationContext bitbucketAuthenticationContext;
    private final PluginSettingsFactory pluginSettingsFactory;


    public BitbucketSAMLLoginFilter(I18nService i18nService,
                                    PluginSettingsFactory pluginSettingsFactory,
                                    UserService userService,
                                    AuthenticationContext bitbucketAuthenticationContext ){
        this.i18nService = i18nService;
        this.pluginSettingsFactory = pluginSettingsFactory;
        this.userService = userService;
        this.bitbucketAuthenticationContext = bitbucketAuthenticationContext;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        //boolean idpRequired = true;

        HttpServletRequest req = (HttpServletRequest)request;
        HttpServletResponse res = (HttpServletResponse)response;

        PluginSettings settings = pluginSettingsFactory.createGlobalSettings();
        String idpRequired = (String) settings.get(PLUGIN_STORAGE_KEY + ".enforceSSO");
        if (idpRequired != null & idpRequired.equalsIgnoreCase("true")){
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