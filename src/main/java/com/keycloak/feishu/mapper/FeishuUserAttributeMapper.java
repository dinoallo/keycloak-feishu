package com.keycloak.feishu.mapper;

import com.fasterxml.jackson.databind.JsonNode;

import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Mapper that reads Feishu user_info fields and stores them as
 * Keycloak user attributes.
 *
 * <p>This mapper is automatically invoked for every Feishu IdP login.
 * It extracts the raw Feishu user info JSON (stored by
 * {@link com.keycloak.feishu.FeishuIdentityProvider}) and applies the
 * user-configurable attribute mapping rules.</p>
 *
 * <h3>Default Mappings</h3>
 * <p>When no explicit mapping rules are configured, the following defaults
 * are applied:</p>
 * <table>
 *   <tr><th>Feishu Field</th><th>Keycloak Attribute</th></tr>
 *   <tr><td>sub</td><td>feishu_sub</td></tr>
 *   <tr><td>open_id</td><td>feishu_open_id</td></tr>
 *   <tr><td>union_id</td><td>feishu_union_id</td></tr>
 *   <tr><td>name</td><td>feishu_name</td></tr>
 *   <tr><td>en_name</td><td>feishu_en_name</td></tr>
 *   <tr><td>nickname</td><td>feishu_nickname</td></tr>
 *   <tr><td>email</td><td>feishu_email</td></tr>
 *   <tr><td>mobile</td><td>feishu_mobile</td></tr>
 *   <tr><td>tenant_key</td><td>feishu_tenant_key</td></tr>
 *   <tr><td>avatar_url</td><td>feishu_avatar_url</td></tr>
 *   <tr><td>avatar_thumb</td><td>feishu_avatar_thumb</td></tr>
 *   <tr><td>avatar_middle</td><td>feishu_avatar_middle</td></tr>
 *   <tr><td>avatar_big</td><td>feishu_avatar_big</td></tr>
 *   <tr><td>user_id</td><td>feishu_user_id</td></tr>
 * </table>
 */
public class FeishuUserAttributeMapper extends AbstractIdentityProviderMapper {

    private static final String PROVIDER_ID = "feishu-user-attribute-mapper";
    private static final String PROVIDER_NAME = "Feishu User Attribute Mapper";
    private static final String HELPER_TEXT =
            "Maps Feishu user_info fields to Keycloak user attributes. " +
            "The mapper prefix \"feishu_\" is added automatically.";

    private static final String PROP_FEISHU_USER_INFO = "feishuUserInfo";

    // ---- Config property keys ----

    private static final String CONF_ATTRIBUTE_PREFIX = "attribute.prefix";
    private static final String CONF_ATTRIBUTE_PREFIX_DEFAULT = "feishu_";

    private static final String CONF_FIELDS = "fields";

    // ========================================================================
    // IdentityProviderMapper SPI
    // ========================================================================

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return PROVIDER_NAME;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Mapper";
    }

    @Override
    public String getHelpText() {
        return HELPER_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(CONF_ATTRIBUTE_PREFIX)
                .label("Attribute prefix")
                .helpText("Prefix added before the Feishu field name when " +
                        "storing as a Keycloak user attribute. Default: feishu_")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue(CONF_ATTRIBUTE_PREFIX_DEFAULT)
                .add()
                .property()
                .name(ConfigConstants.MAP_ATTRIBUTES)
                .label("Map attributes from Feishu user info")
                .helpText("If enabled, all available Feishu fields are " +
                        "mapped as user attributes. If disabled, no " +
                        "attributes are mapped.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("true")
                .add()
                .build();
    }

    // ========================================================================
    // Mapping logic
    // ========================================================================

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm,
                              UserModel user, BrokeredIdentityContext context) {
        applyMapping(user, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm,
                                   UserModel user, BrokeredIdentityContext context) {
        applyMapping(user, context);
    }

    @Override
    public Object updateBrokeredUserLegacy(KeycloakSession session, RealmModel realm,
                                           UserModel user, BrokeredIdentityContext context) {
        applyMapping(user, context);
        return null;
    }

    /**
     * Apply the Feishu attribute mapping to the Keycloak user.
     */
    private void applyMapping(UserModel user, BrokeredIdentityContext context) {
        // Retrieve the raw Feishu user info JSON stored by the provider
        JsonNode userInfo = (JsonNode) context.getContext().get(PROP_FEISHU_USER_INFO);
        if (userInfo == null) {
            return;
        }

        String prefix = Optional.ofNullable(context.getMapperConfig())
                .map(cfg -> cfg.getConfig().get(CONF_ATTRIBUTE_PREFIX))
                .orElse(CONF_ATTRIBUTE_PREFIX_DEFAULT);

        boolean mapAttributes = parseBooleanConfig(context, ConfigConstants.MAP_ATTRIBUTES, true);
        if (!mapAttributes) {
            return;
        }

        // Define the fields to extract
        String[] fields = {
                "sub", "name", "en_name", "nickname",
                "email", "mobile", "open_id", "union_id",
                "tenant_key", "avatar_url", "avatar_thumb",
                "avatar_middle", "avatar_big", "user_id"
        };

        for (String field : fields) {
            String value = getField(userInfo, field);
            if (value != null) {
                String attributeName = prefix + field;
                user.setSingleAttribute(attributeName, value);
            }
        }
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    private static boolean parseBooleanConfig(BrokeredIdentityContext context,
                                               String key, boolean defaultValue) {
        if (context.getMapperConfig() == null
                || context.getMapperConfig().getConfig() == null) {
            return defaultValue;
        }
        String val = context.getMapperConfig().getConfig().get(key);
        return val != null ? Boolean.parseBoolean(val) : defaultValue;
    }

    private static String getField(JsonNode node, String field) {
        if (node == null || !node.has(field) || node.get(field).isNull()) {
            return null;
        }
        return node.get(field).asText();
    }
}
