package com.keycloak.feishu;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Feishu user_info JSON parsing.
 *
 * Verifies that the exact response format returned by the Feishu
 * /open-apis/authen/v1/user_info API is correctly parsed.
 */
class FeishuUserInfoParsingTest {

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Response format from Feishu API (all values sanitized / fake):
     * {code, msg, data: {avatar_*, email, en_name, mobile, name, open_id, tenant_key, union_id, user_id}}
     */
    private static final String ACTUAL_FEISHU_RESPONSE = """
            {
              "code": 0,
              "data": {
                "avatar_big": "https://example.com/avatar/big.png",
                "avatar_middle": "https://example.com/avatar/mid.png",
                "avatar_thumb": "https://example.com/avatar/thumb.png",
                "avatar_url": "https://example.com/avatar/thumb.png",
                "email": "",
                "en_name": "TestUser",
                "mobile": "+8610000000000",
                "name": "测试用户",
                "open_id": "ou_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "tenant_key": "tt_aaaaaaaaaaaaaa",
                "union_id": "on_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "user_id": "usr_000001"
              },
              "msg": "success"
            }
            """;

    /** Flat (unwrapped) format that some older Feishu versions may return. */
    private static final String FLAT_USER_INFO = """
            {
                "name": "测试用户",
                "en_name": "TestUser",
                "email": "testuser@example.com",
                "mobile": "+8610000000001",
                "open_id": "ou_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "union_id": "on_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "tenant_key": "tt_bbbbbbbbbbbbbb",
                "avatar_url": "https://example.com/avatar/url.png",
                "avatar_thumb": "https://example.com/avatar/thumb.png",
                "avatar_middle": "https://example.com/avatar/mid.png",
                "avatar_big": "https://example.com/avatar/big.png",
                "user_id": "usr_000002"
            }
            """;

    private JsonNode dataNode;       // unwrapped data from the wrapped response
    private JsonNode rootNode;       // full wrapped response
    private JsonNode flatNode;       // flat (unwrapped) response

    @BeforeEach
    void setUp() throws Exception {
        rootNode = mapper.readTree(ACTUAL_FEISHU_RESPONSE);
        dataNode = rootNode.get("data");
        flatNode = mapper.readTree(FLAT_USER_INFO);
    }

    // ====================================================================
    // Wrapped response format  {code:0, msg:"ok", data:{...}}
    // ====================================================================

    @Test
    void shouldParseEnvelopeCodeAndMsg() {
        assertEquals(0, rootNode.get("code").asInt());
        assertEquals("success", rootNode.get("msg").asText());
        assertTrue(rootNode.get("data").isObject());
    }

    @Test
    void shouldParseAllFieldsFromWrappedResponse() {
        assertNotNull(dataNode);
        assertEquals("测试用户", getField(dataNode, "name"));
        assertEquals("TestUser", getField(dataNode, "en_name"));
        assertEquals("+8610000000000", getField(dataNode, "mobile"));
        assertEquals("ou_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", getField(dataNode, "open_id"));
        assertEquals("on_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", getField(dataNode, "union_id"));
        assertEquals("tt_aaaaaaaaaaaaaa", getField(dataNode, "tenant_key"));
        assertEquals("usr_000001", getField(dataNode, "user_id"));
    }

    @Test
    void shouldParseAllAvatarVariants() {
        assertEquals("https://example.com/avatar/big.png", getField(dataNode, "avatar_big"));
        assertEquals("https://example.com/avatar/mid.png", getField(dataNode, "avatar_middle"));
        assertEquals("https://example.com/avatar/thumb.png", getField(dataNode, "avatar_thumb"));
        assertEquals("https://example.com/avatar/thumb.png", getField(dataNode, "avatar_url"));
    }

    @Test
    void shouldTreatEmptyEmailAsNull() {
        assertNull(getField(dataNode, "email"));
    }

    @Test
    void shouldReturnNullForMissingField() {
        // "sub" and "nickname" are not in this response
        assertNull(getField(dataNode, "sub"));
        assertNull(getField(dataNode, "nickname"));
    }

    // ====================================================================
    // Flat (unwrapped) response format
    // ====================================================================

    @Test
    void shouldParseAllFieldsFromFlatResponse() {
        assertEquals("测试用户", getField(flatNode, "name"));
        assertEquals("TestUser", getField(flatNode, "en_name"));
        assertEquals("testuser@example.com", getField(flatNode, "email"));
        assertEquals("+8610000000001", getField(flatNode, "mobile"));
        assertEquals("ou_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", getField(flatNode, "open_id"));
        assertEquals("on_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", getField(flatNode, "union_id"));
        assertEquals("tt_bbbbbbbbbbbbbb", getField(flatNode, "tenant_key"));
        assertEquals("usr_000002", getField(flatNode, "user_id"));
    }

    @Test
    void shouldPickAvatarBigFirst() {
        String picked = pickAvatar(flatNode);
        assertTrue(picked.contains("big"));
    }

    @Test
    void shouldFallbackAvatarWhenBigMissing() throws Exception {
        String noBig = """
                {"avatar_middle": "https://example.com/avatar/mid.png",
                 "avatar_url": "https://example.com/avatar/url.png"}
                """;
        JsonNode node = mapper.readTree(noBig);
        String picked = pickAvatar(node);
        assertEquals("https://example.com/avatar/mid.png", picked);
    }

    // ====================================================================
    // Edge cases
    // ====================================================================

    @Test
    void shouldReturnNullForNullField() throws Exception {
        String jsonWithNull = """
                {"name": null, "open_id": "ou_test_valid"}
                """;
        JsonNode node = mapper.readTree(jsonWithNull);
        assertNull(getField(node, "name"));
        assertEquals("ou_test_valid", getField(node, "open_id"));
    }

    @Test
    void shouldNotThrowOnEmptyResponse() throws Exception {
        JsonNode empty = mapper.readTree("{}");
        assertNull(getField(empty, "sub"));
        assertNull(getField(empty, "open_id"));
        assertNull(getField(empty, "name"));
    }

    @Test
    void shouldHandleExtraUnexpectedFields() throws Exception {
        String jsonWithExtra = """
                {
                    "open_id": "ou_test_extra",
                    "name": "Test",
                    "extra_field_1": "value1",
                    "extra_field_2": ["a", "b"]
                }
                """;
        JsonNode node = mapper.readTree(jsonWithExtra);
        assertEquals("ou_test_extra", getField(node, "open_id"));
        assertEquals("Test", getField(node, "name"));
        assertNotNull(node.get("extra_field_1"));
        assertTrue(node.get("extra_field_2").isArray());
    }

    @Test
    void shouldMapAllFieldsToAttributes() throws Exception {
        // Simulate what FeishuIdentityProvider.mapUserInfoToAttributes does
        Map<String, String> attributes = new HashMap<>();

        String[] fields = {
                "sub", "name", "en_name", "nickname",
                "email", "mobile", "open_id", "union_id",
                "tenant_key", "avatar_url", "avatar_thumb",
                "avatar_middle", "avatar_big", "user_id"
        };

        for (String field : fields) {
            String val = getField(flatNode, field);
            if (val != null) {
                attributes.put(field, val);
            }
        }

        // flatNode has all fields except sub and nickname
        assertEquals(12, attributes.size(),
                "12 fields should be extracted (all except sub and nickname)");
        assertEquals("测试用户", attributes.get("name"));
        assertEquals("ou_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", attributes.get("open_id"));
    }

    // ====================================================================
    // Avatar selection logic (matches the provider)
    // ====================================================================

    private static String pickAvatar(JsonNode userInfo) {
        String avatar = getField(userInfo, "avatar_big");
        if (avatar != null) return avatar;
        avatar = getField(userInfo, "avatar_middle");
        if (avatar != null) return avatar;
        avatar = getField(userInfo, "avatar_thumb");
        if (avatar != null) return avatar;
        return getField(userInfo, "avatar_url");
    }

    // ====================================================================
    // Helper: same logic as FeishuIdentityProvider.getField()
    // ====================================================================

    private static String getField(JsonNode node, String field) {
        if (node == null || !node.has(field) || node.get(field).isNull()) {
            return null;
        }
        String value = node.get(field).asText();
        if (value.isBlank()) {
            return null;
        }
        return value;
    }
}
