package com.keycloak.feishu;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 * Factory for registering the Feishu Identity Provider in Keycloak.
 *
 * <p>This class is discovered via the SPI file
 * {@code META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory}
 * and makes the "feishu" provider available in the Keycloak admin console
 * under Identity Providers.
 */
public class FeishuIdentityProviderFactory
        extends AbstractIdentityProviderFactory<FeishuIdentityProvider>
        implements SocialIdentityProviderFactory<FeishuIdentityProvider> {

    public static final String PROVIDER_ID = "feishu";
    public static final String PROVIDER_NAME = "Feishu (Lark)";

    // ---- Config property names (must match FeishuIdentityProviderConfig keys) ----

    static final String CONFIG_APP_ID = "feishuAppId";
    static final String CONFIG_APP_SECRET = "feishuAppSecret";
    static final String CONFIG_AUTH_URL = "feishuAuthUrl";
    static final String CONFIG_TOKEN_URL = "feishuTokenUrl";
    static final String CONFIG_USER_INFO_URL = "feishuUserInfoUrl";
    static final String CONFIG_USER_ID = "feishuUserIdFeature";

    private static final String DEFAULT_AUTH_URL =
            "https://accounts.feishu.cn/open-apis/authen/v1/authorize";
    private static final String DEFAULT_TOKEN_URL =
            "https://accounts.feishu.cn/oauth/v3/token";
    private static final String DEFAULT_USER_INFO_URL =
            "https://open.feishu.cn/open-apis/authen/v1/user_info";

    // ========================================================================
    // IdentityProviderFactory
    // ========================================================================

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public FeishuIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        FeishuIdentityProviderConfig config = new FeishuIdentityProviderConfig(model);
        return new FeishuIdentityProvider(session, config);
    }

    @Override
    public FeishuIdentityProviderConfig createConfig() {
        return new FeishuIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()

                // ---- Credentials ----

                .property()
                .name(CONFIG_APP_ID)
                .label("Feishu App ID")
                .helpText("The App ID of your Feishu application. " +
                        "Find this on the Feishu Open Platform console " +
                        "(https://open.feishu.cn/app) under Credentials.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .add()

                .property()
                .name(CONFIG_APP_SECRET)
                .label("Feishu App Secret")
                .helpText("The App Secret of your Feishu application. " +
                        "Keep this value confidential.")
                .type(ProviderConfigProperty.PASSWORD)
                .secret(true)
                .add()

                // ---- Endpoint URLs ----

                .property()
                .name(CONFIG_AUTH_URL)
                .label("Authorization endpoint URL")
                .helpText("Feishu OAuth2 authorization endpoint. " +
                        "Change this if using a custom domain, proxy, " +
                        "or the international larksuite.com base URL.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_AUTH_URL)
                .add()

                .property()
                .name(CONFIG_TOKEN_URL)
                .label("Token endpoint URL")
                .helpText("Feishu OAuth2 token endpoint. " +
                        "Change this if using a custom domain, proxy, " +
                        "or the international larksuite.com base URL.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_TOKEN_URL)
                .add()

                .property()
                .name(CONFIG_USER_INFO_URL)
                .label("User info endpoint URL")
                .helpText("Feishu user info endpoint. " +
                        "Change this if using a custom domain, proxy, " +
                        "or the international larksuite.com base URL.")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(DEFAULT_USER_INFO_URL)
                .add()

                // ---- Feature flags ----

                .property()
                .name(CONFIG_USER_ID)
                .label("Fetch Feishu user_id (employee ID)")
                .helpText("When enabled, the provider requests additional " +
                        "scope (contact:user.employee_id:readall) and maps " +
                        "the Feishu user_id field. Requires the contact " +
                        "permission scope to be granted in the Feishu app.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()

                .build();
    }
}
