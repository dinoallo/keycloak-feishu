package com.keycloak.feishu;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Feishu (Lark) Identity Provider.
 *
 * Implements the OAuth2 authorization-code flow against Feishu Open Platform,
 * retrieves the user info via the Feishu authentication API, and parses all
 * returned fields into Keycloak user attributes.
 *
 * <h3>Endpoints (configurable via {@link FeishuIdentityProviderConfig})</h3>
 * <ul>
 *   <li>Authorize:  defaults to {@code https://accounts.feishu.cn/open-apis/authen/v1/authorize}</li>
 *   <li>Token:      defaults to {@code https://accounts.feishu.cn/oauth/v3/token}</li>
 *   <li>User Info:  defaults to {@code https://open.feishu.cn/open-apis/authen/v1/user_info}</li>
 * </ul>
 */
public class FeishuIdentityProvider extends AbstractOAuth2IdentityProvider<FeishuIdentityProviderConfig>
        implements SocialIdentityProvider<FeishuIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(FeishuIdentityProvider.class);

    // ---- Feishu user_info response fields ----
    private static final String FLD_SUB = "sub";
    private static final String FLD_NAME = "name";
    private static final String FLD_EN_NAME = "en_name";
    private static final String FLD_NICKNAME = "nickname";
    private static final String FLD_EMAIL = "email";
    private static final String FLD_MOBILE = "mobile";
    private static final String FLD_OPEN_ID = "open_id";
    private static final String FLD_UNION_ID = "union_id";
    private static final String FLD_TENANT_KEY = "tenant_key";
    private static final String FLD_AVATAR_URL = "avatar_url";
    private static final String FLD_AVATAR_THUMB = "avatar_thumb";
    private static final String FLD_AVATAR_MIDDLE = "avatar_middle";
    private static final String FLD_AVATAR_BIG = "avatar_big";
    private static final String FLD_USER_ID = "user_id";

    private static final String PROP_FEISHU_USER_INFO = "feishuUserInfo";
    private static final ObjectMapper mapper = new ObjectMapper();

    public FeishuIdentityProvider(KeycloakSession session, FeishuIdentityProviderConfig config) {
        super(session, config);
    }

    // ========================================================================
    // AbstractOAuth2IdentityProvider overrides
    // ========================================================================

    @Override
    protected String getAuthUrl() {
        return getConfig().getFeishuAuthUrl();
    }

    @Override
    protected String getTokenUrl() {
        return getConfig().getFeishuTokenUrl();
    }

    @Override
    protected String getUserInfoUrl() {
        return getConfig().getFeishuUserInfoUrl();
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    /**
     * Build the authorization URL with Feishu-specific parameters.
     *
     * Feishu requires {@code app_id} (not {@code client_id}) as the
     * application identifier parameter.  We also pass the configured
     * default scope.
     */
    @Override
    protected String getAuthUrl(String redirectUri, String state, String loginHint) {
        FeishuIdentityProviderConfig config = getConfig();

        String url = getAuthUrl()
                + "?app_id=" + encodeParam(config.getFeishuAppId())
                + "&redirect_uri=" + encodeParam(redirectUri)
                + "&state=" + encodeParam(state)
                + "&response_type=code"
                + "&scope=" + encodeParam(config.getDefaultScope());

        String prompt = config.getPrompt();
        if (prompt != null && !prompt.isEmpty()) {
            url = url + "&prompt=" + encodeParam(prompt);
        }
        return url;
    }

    /**
     * Feishu's token endpoint uses {@code app_id} / {@code app_secret}
     * credentials encoded in the POST body (JSON), not Basic Auth with
     * client_id / client_secret.
     */
    @Override
    protected String exchangeCodeForToken(KeycloakSession session, EventBuilder event, String code) {
        FeishuIdentityProviderConfig config = getConfig();

        try {
            Map<String, String> params = new HashMap<>();
            params.put("app_id", config.getFeishuAppId());
            params.put("app_secret", config.getFeishuAppSecret());
            params.put("grant_type", "authorization_code");
            params.put("code", code);

            SimpleHttp http = SimpleHttp.doPost(getTokenUrl(), session)
                    .json(mapper.valueToTree(params));

            String response = http.asString();

            JsonNode tokenJson = mapper.readTree(response);

            // Feishu returns: {"code":0,"msg":"ok","data":{"access_token":"...","token_type":"Bearer","expires_in":...}}
            int feishuCode = tokenJson.has("code") ? tokenJson.get("code").asInt() : -1;
            if (feishuCode != 0) {
                String msg = tokenJson.has("msg") ? tokenJson.get("msg").asText() : "unknown error";
                logger.errorf("Feishu token exchange failed: code=%d, msg=%s", feishuCode, msg);
                throw new IdentityBrokerException("Feishu token exchange failed: " + msg);
            }

            JsonNode data = tokenJson.get("data");
            if (data == null || !data.has("access_token")) {
                logger.errorf("Feishu token response missing data.access_token: %s", response);
                throw new IdentityBrokerException("Feishu token response missing access_token");
            }

            return data.get("access_token").asText();
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Feishu token exchange request failed", e);
            throw new IdentityBrokerException("Failed to exchange code for token", e);
        }
    }

    /**
     * Fetch the Feishu user info and build a {@link BrokeredIdentityContext}.
     *
     * Calls Feishu's user_info endpoint with the access token,
     * parses the response, and maps all available fields to Keycloak attributes.
     * The raw JSON is also stored as {@code feishuUserInfo} for use by mappers.
     */
    @Override
    protected BrokeredIdentityContext getFederatedIdentity(String accessToken) {
        try {
            JsonNode userInfo = fetchUserInfo(accessToken);
            return buildFederatedIdentity(userInfo, accessToken);
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            logger.error("Failed to get federated identity from Feishu", e);
            throw new IdentityBrokerException("Failed to get federated identity from Feishu", e);
        }
    }

    /**
     * Build a {@link BrokeredIdentityContext} from the Feishu user_info JSON.
     *
     * This method is also public so that mappers can recompute the profile
     * from stored user info without making an extra HTTP call.
     */
    public BrokeredIdentityContext buildFederatedIdentity(JsonNode userInfo, String accessToken) {
        if (userInfo == null) {
            throw new IdentityBrokerException("Feishu user info is null");
        }

        // Use open_id as the federated user ID (stable across sessions)
        String openId = getField(userInfo, FLD_OPEN_ID);
        if (openId == null) {
            openId = getField(userInfo, FLD_SUB);
        }
        if (openId == null) {
            throw new IdentityBrokerException(
                    "Feishu user info missing both open_id and sub");
        }

        BrokeredIdentityContext identity = new BrokeredIdentityContext(openId);
        identity.setIdpConfig(getConfig());
        identity.setIdp(this);
        identity.setBrokerUserId(openId);

        // ---- Profile fields ----
        String name = getField(userInfo, FLD_NAME);
        String enName = getField(userInfo, FLD_EN_NAME);
        String email = getField(userInfo, FLD_EMAIL);

        identity.setUsername(name != null ? name : enName);
        identity.setFirstName(name);
        // Use en_name as lastName if available; otherwise fall back to name
        identity.setLastName(enName != null ? enName : name);

        // Only set email if it's non-blank (Feishu may return "")
        if (email != null && !email.isBlank()) {
            identity.setEmail(email);
        }

        // ---- Avatar: prefer largest variant ----
        String avatar = pickAvatar(userInfo);
        if (avatar != null) {
            identity.setAvatar(URI.create(avatar));
        }

        // ---- Store raw JSON for attribute mappers ----
        identity.getContext().put(PROP_FEISHU_USER_INFO, userInfo);

        // ---- Extract all Feishu fields as Keycloak user attributes ----
        mapUserInfoToAttributes(identity, userInfo);

        return identity;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /**
     * Call the Feishu user_info API and return the {@code data} payload.
     *
     * Handles both wrapped responses (<code>{"code":0,"msg":"ok","data":{...}}</code>)
     * and flat responses.
     */
    private JsonNode fetchUserInfo(String accessToken) throws Exception {
        SimpleHttp http = SimpleHttp.doGet(getUserInfoUrl(), session)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/json; charset=utf-8");

        String response = http.asString();
        logger.debugf("Feishu user_info response: %s", response);

        JsonNode root = mapper.readTree(response);

        // Check for Feishu API-level error
        if (root.has("code") && root.get("code").asInt() != 0) {
            String msg = root.has("msg") ? root.get("msg").asText() : "unknown error";
            logger.errorf("Feishu user_info API error: code=%d, msg=%s",
                    root.get("code").asInt(), msg);
            throw new IdentityBrokerException("Feishu user_info API error: " + msg);
        }

        // Unwrap {code, msg, data} envelope
        if (root.has("data") && root.get("data").isObject()) {
            return root.get("data");
        }

        return root;
    }

    /**
     * Parse all known fields from the Feishu user_info response and set them
     * as Keycloak user attributes on the identity context.
     */
    private void mapUserInfoToAttributes(BrokeredIdentityContext identity, JsonNode userInfo) {
        String[] fields = {
                FLD_SUB, FLD_NAME, FLD_EN_NAME, FLD_NICKNAME,
                FLD_EMAIL, FLD_MOBILE, FLD_OPEN_ID, FLD_UNION_ID,
                FLD_TENANT_KEY, FLD_AVATAR_URL, FLD_AVATAR_THUMB,
                FLD_AVATAR_MIDDLE, FLD_AVATAR_BIG, FLD_USER_ID
        };

        for (String field : fields) {
            String value = getField(userInfo, field);
            if (value != null && !value.isBlank()) {
                identity.setUserAttribute(field, value);
            }
        }
    }

    /**
     * Pick the best avatar URL: big > middle > thumb > url.
     */
    private static String pickAvatar(JsonNode userInfo) {
        String avatar = getField(userInfo, FLD_AVATAR_BIG);
        if (avatar != null) return avatar;
        avatar = getField(userInfo, FLD_AVATAR_MIDDLE);
        if (avatar != null) return avatar;
        avatar = getField(userInfo, FLD_AVATAR_THUMB);
        if (avatar != null) return avatar;
        return getField(userInfo, FLD_AVATAR_URL);
    }

    /**
     * Safe field accessor that handles missing, null, and empty-string values.
     */
    private static String getField(JsonNode node, String field) {
        if (node == null || !node.has(field) || node.get(field).isNull()) {
            return null;
        }
        String value = node.get(field).asText();
        // Treat blank strings as "not present" for most purposes.
        if (value.isBlank()) {
            return null;
        }
        return value;
    }

    /**
     * URL-encode a value for use in OAuth2 parameter positions.
     */
    private static String encodeParam(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    // ========================================================================
    // SimpleHttp configuration
    // ========================================================================

    @Override
    protected void configureHttpRequest(SimpleHttp request, String accessToken) {
        request.header("Authorization", "Bearer " + accessToken);
        request.header("Content-Type", "application/json; charset=utf-8");
    }
}
