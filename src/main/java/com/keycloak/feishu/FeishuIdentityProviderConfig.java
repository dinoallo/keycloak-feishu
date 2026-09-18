package com.keycloak.feishu;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Configuration model for Feishu Identity Provider.
 *
 * Stores Feishu-specific settings such as app_id, app_secret,
 * endpoint URLs, and optional features like user ID binding mode.
 */
public class FeishuIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    private static final String APP_ID_CONFIG_KEY = "feishuAppId";
    private static final String APP_SECRET_CONFIG_KEY = "feishuAppSecret";
    private static final String USER_ID_FEATURE_KEY = "feishuUserIdFeature";

    // ---- Configurable endpoint URLs ----

    private static final String AUTH_URL_KEY = "feishuAuthUrl";
    private static final String TOKEN_URL_KEY = "feishuTokenUrl";
    private static final String USER_INFO_URL_KEY = "feishuUserInfoUrl";

    private static final String DEFAULT_AUTH_URL =
            "https://accounts.feishu.cn/open-apis/authen/v1/authorize";
    private static final String DEFAULT_TOKEN_URL =
            "https://accounts.feishu.cn/oauth/v3/token";
    private static final String DEFAULT_USER_INFO_URL =
            "https://open.feishu.cn/open-apis/authen/v1/user_info";

    public FeishuIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public FeishuIdentityProviderConfig() {
        super();
    }

    // ========================================================================
    // Feishu App ID
    // ========================================================================

    public String getFeishuAppId() {
        return getConfig().get(APP_ID_CONFIG_KEY);
    }

    public void setFeishuAppId(String appId) {
        getConfig().put(APP_ID_CONFIG_KEY, appId);
    }

    // ========================================================================
    // Feishu App Secret
    // ========================================================================

    public String getFeishuAppSecret() {
        return getConfig().get(APP_SECRET_CONFIG_KEY);
    }

    public void setFeishuAppSecret(String appSecret) {
        getConfig().put(APP_SECRET_CONFIG_KEY, appSecret);
    }

    // ========================================================================
    // Configurable Endpoint URLs
    //
    // Each URL defaults to the standard Feishu Open Platform endpoint.
    // Users can override these to point to a different base domain
    // (e.g., larksuite.com for international tenants) or a custom proxy.
    // ========================================================================

    public String getFeishuAuthUrl() {
        return getConfig().getOrDefault(AUTH_URL_KEY, DEFAULT_AUTH_URL);
    }

    public void setFeishuAuthUrl(String url) {
        getConfig().put(AUTH_URL_KEY, url);
    }

    public String getFeishuTokenUrl() {
        return getConfig().getOrDefault(TOKEN_URL_KEY, DEFAULT_TOKEN_URL);
    }

    public void setFeishuTokenUrl(String url) {
        getConfig().put(TOKEN_URL_KEY, url);
    }

    public String getFeishuUserInfoUrl() {
        return getConfig().getOrDefault(USER_INFO_URL_KEY, DEFAULT_USER_INFO_URL);
    }

    public void setFeishuUserInfoUrl(String url) {
        getConfig().put(USER_INFO_URL_KEY, url);
    }

    // ========================================================================
    // User ID Feature Flag
    //
    // When enabled, the provider requests additional scope
    // (contact:user.employee_id:readall) to retrieve the Feishu user_id
    // (employee ID bound to the tenant's app).
    // ========================================================================

    public boolean isUserIdFeatureEnabled() {
        return Boolean.parseBoolean(
                getConfig().getOrDefault(USER_ID_FEATURE_KEY, "false"));
    }

    public void setUserIdFeatureEnabled(boolean enabled) {
        getConfig().put(USER_ID_FEATURE_KEY, String.valueOf(enabled));
    }

    /**
     * Returns the default scopes used by the Feishu IdP.
     * <ul>
     *   <li>{@code user_info} – required, returns open_id, union_id, name, avatar</li>
     *   <li>{@code contact:user.employee_id:readall} – optional, enables user_id binding</li>
     * </ul>
     */
    public String getDefaultScope() {
        return isUserIdFeatureEnabled()
                ? "user_info contact:user.employee_id:readall"
                : "user_info";
    }
}
