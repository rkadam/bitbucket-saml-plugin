# bitbucket-saml-plugin
SAML Connector to enable using Bitbucket server with Single Signon / Identity Provider

#### Deploying / Using this plugin with your Bitbucket Server
* Make sure you have *ip-metadata.xml* and *sp-metadata.xml* available within your application.
  * For example these files can be put into base directory of standard Bitbucket installation.
  * ip-metadata.xml provides information about your IDP Provider and how it's configured to connect to Bitbucket server.
    * Should contain information such as x509 certificate, HTTP-POST/Redirect/SOAP Binding information for SingleSignOnService and SingleLogoutService
  * sp-metadata.xml provides information about Bitbucket (aka Service Provider)
    * Make sure AssertionConsumerService location URL should be same as callback URL from IDP
* Download saml.plugin-0.0.1-SNAPSHOT.jar available from releases section.
* Upload it into your Bitbucket server via *Manage add-ons* -> *upload add-ons*

#### Steps to build this plugin locally
* This plugin uses this [JAVA SAML Toolkit](https://github.com/lastpass/saml-sdk-java/)
  * To compile bitbucket-saml-plugin, locally you will need _JAVA SAML Toolkit_ available in your Maven Repository.
  * Here quick steps to achieve same
    * ``git clone https://github.com/lastpass/saml-sdk-java.git lastpass-saml-sdk-java``
    * Build a jar by running ``ant`` within this directory.
    * Now put this jar into local maven repository as mentioned [here](https://maven.apache.org/guides/mini/guide-3rd-party-jars-local.html)
      >``mvn install:install-file -Dfile=\<base location\>/out/lastpass-saml-sdk-0.3.0.jar -DpomFile=\<base location\>/pom.xml``
  * Package plugin jar using following command
  ``mvn package``





