package team.effort.bitbucket.config;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import com.google.common.collect.Maps;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.atlassian.bitbucket.user.SecurityService;
import com.atlassian.sal.api.auth.LoginUriProvider;
import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.atlassian.sal.api.user.UserManager;
import com.atlassian.sal.api.user.UserProfile;
import com.atlassian.templaterenderer.TemplateRenderer;

import static team.effort.bitbucket.config.BitbucketSAMLAdminConfigResource.isAdminUser;


public class BitbucketSAMLAdminServlet extends HttpServlet {

    private final TemplateRenderer renderer;
    private final UserManager userManager;
    private final LoginUriProvider loginUriProvider;

    public static final String PLUGIN_STORAGE_KEY = "team.effort.bitbucket.config";


    public BitbucketSAMLAdminServlet(TemplateRenderer renderer,
                                     UserManager userManager,
                                     LoginUriProvider loginUriProvider){
        this.renderer = renderer;
        this.userManager = userManager;
        this.loginUriProvider = loginUriProvider;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException{
        if(!isAdminUser(userManager, request)){
            redirectToLogin(request, response);
            return;
        }

        response.setContentType("text/html;charset=utf-8");
        renderer.render("static/admin/saml-admin.vm", response.getWriter());
    }

    private void redirectToLogin(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        response.sendRedirect(loginUriProvider.getLoginUri(getUri(request)).toASCIIString());
    }

    private URI getUri(HttpServletRequest request)
    {
        StringBuffer builder = request.getRequestURL();
        if (request.getQueryString() != null)
        {
            builder.append("?");
            builder.append(request.getQueryString());
        }
        return URI.create(builder.toString());
    }

}