package team.effort.bitbucket.config;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.atlassian.sal.api.pluginsettings.PluginSettings;
import com.atlassian.sal.api.pluginsettings.PluginSettingsFactory;
import com.atlassian.sal.api.transaction.TransactionCallback;
import com.atlassian.sal.api.transaction.TransactionTemplate;
import com.atlassian.sal.api.user.UserManager;
import com.atlassian.sal.api.user.UserProfile;

import static team.effort.bitbucket.config.BitbucketSAMLAdminServlet.PLUGIN_STORAGE_KEY;

@Path("/config")
public class BitbucketSAMLAdminConfigResource
{
    private final UserManager userManager;
    private final PluginSettingsFactory pluginSettingsFactory;
    private final TransactionTemplate transactionTemplate;

    public BitbucketSAMLAdminConfigResource(UserManager userManager,
                                            PluginSettingsFactory pluginSettingsFactory,
                                            TransactionTemplate transactionTemplate)
    {
        this.userManager = userManager;
        this.pluginSettingsFactory = pluginSettingsFactory;
        this.transactionTemplate = transactionTemplate;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response get(@Context HttpServletRequest request)
    {
        if(!isAdminUser(userManager, request)){
            return Response.status(Status.UNAUTHORIZED).build();
        }

        return Response.ok(transactionTemplate.execute(new TransactionCallback()
        {
            public Object doInTransaction()
            {
                PluginSettings settings = pluginSettingsFactory.createGlobalSettings();
                Config config = new Config();
                config.setEnforceSSO((String) settings.get(PLUGIN_STORAGE_KEY + ".enforceSSO"));

                return config;
            }
        })).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response put(final Config config, @Context HttpServletRequest request)
    {
        if(!isAdminUser(userManager, request)){
            return Response.status(Status.UNAUTHORIZED).build();
        }

        transactionTemplate.execute(new TransactionCallback()
        {
            public Object doInTransaction()
            {
                PluginSettings pluginSettings = pluginSettingsFactory.createGlobalSettings();
                pluginSettings.put(PLUGIN_STORAGE_KEY + ".enforceSSO", config.getEnforceSSO());
                return null;
            }
        });
        return Response.noContent().build();
    }

    public static boolean isAdminUser(UserManager userManager, HttpServletRequest request) {
        try {
            final UserProfile user = userManager.getRemoteUser(request);
            if (user == null) {
                return false;
            }
            return userManager.isSystemAdmin(user.getUserKey());
        }
        catch(Exception e){
            e.printStackTrace();
            return false;
        }
    }


    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Config
    {
        @XmlElement private String enforceSSO;

        public String getEnforceSSO()
        {
            return enforceSSO;
        }

        public void setEnforceSSO(String enforceSSO)
        {
            this.enforceSSO = enforceSSO;
        }
    }
}
