# keycloak-feishu

Support Feishu/Lark as an identity provider on Keycloak.

## Overview

This project provides a **Keycloak SPI** that adds Feishu (飞书 / Lark) as a
social/identity provider. It implements the OAuth2 authorization-code flow
against the Feishu Open Platform and maps the Feishu `user_info` API response
fields into Keycloak user attributes.

All API endpoints are configurable, making it easy to switch between
`feishu.cn` (Chinese mainland), `larksuite.com` (international), or a
custom proxy.

## Requirements

- **Keycloak** 22+ (tested with Keycloak 25)
- **Java** 17+
- **Apache Maven** 3.8+

## Build

```bash
mvn clean package
```

The output JAR is `target/keycloak-feishu.jar`.

## Installation

1. Build the JAR (see above) or download a release.
2. Copy `target/keycloak-feishu.jar` into the Keycloak `providers/` directory:

   ```bash
   cp target/keycloak-feishu.jar $KEYCLOAK_HOME/providers/
   ```

3. Restart Keycloak (or run `kc.sh build` for a Quarkus-based distribution):

   ```bash
   $KEYCLOAK_HOME/bin/kc.sh build
   $KEYCLOAK_HOME/bin/kc.sh start
   ```

## Configuration

### 1. Create a Feishu App

1. Go to the [Feishu Open Platform Console](https://open.feishu.cn/app).
2. Create an application (or use an existing one).
3. Under **Security → App Permissions**, enable the following permissions:
   - `user_info` — required
   - `contact:user.employee_id:readall` — only if you need the `user_id` (employee ID) field
4. Under **Security → Redirect URLs**, add your Keycloak redirect URI:
   `https://<your-keycloak>/realms/<realm>/broker/feishu/endpoint`
5. Publish the app.

### 2. Add the Feishu IdP in Keycloak

1. Open the Keycloak Admin Console.
2. Go to your Realm → **Identity Providers**.
3. Click **Add Provider** and select **Feishu (Lark)**.
4. Fill in the required fields:

| Field | Description | Default |
|-------|-------------|---------|
| **Feishu App ID** | Your Feishu application App ID | — |
| **Feishu App Secret** | Your Feishu application App Secret | — |
| **Authorization endpoint URL** | OAuth2 authorization endpoint | `https://accounts.feishu.cn/open-apis/authen/v1/authorize` |
| **Token endpoint URL** | OAuth2 token exchange endpoint | `https://accounts.feishu.cn/oauth/v3/token` |
| **User info endpoint URL** | User info API endpoint | `https://open.feishu.cn/open-apis/authen/v1/user_info` |
| **Fetch Feishu user_id** | Enable user_id (employee ID) mapping | `false` |

5. Set the **Redirect URI** to match what you configured on the Feishu Open Platform.
6. Save.

> **Tip**: For international (Larksuite) tenants, change the three endpoint URLs
> from `open.feishu.cn` to `open.larksuite.com`.

### 3. Optional: Add the Attribute Mapper

After creating the IdP:

1. Go to the **Mappers** tab of your Feishu IdP.
2. Click **Add** → select **Feishu User Attribute Mapper**.
3. Configure the attribute prefix (default: `feishu_`).
4. Save.

## Feishu user_info API Response

The Feishu `/open-apis/authen/v1/user_info` endpoint returns a
wrapped response:

```json
{
  "code": 0,
  "data": {
    "avatar_big": "https://...image_size=640x640...",
    "avatar_middle": "https://...image_size=240x240...",
    "avatar_thumb": "https://...image_size=72x72...",
    "avatar_url": "https://...image_size=72x72...",
    "email": "",
    "en_name": "张三",
    "mobile": "+8611111111111",
    "name": "张三",
    "open_id": "ou_80e18ac8a7cea4d088a50bf86f1e3303",
    "tenant_key": "19cc97fd1f1e1be7",
    "union_id": "on_35f12b736c5326fa0fa81787b60b8698",
    "user_id": "aefbccg3"
  },
  "msg": "success"
}
```

The provider unwraps the `data` object, uses `open_id` as the federated user
identifier, and maps every field to a Keycloak user attribute.

## Field Mapping

| Feishu Field      | Keycloak Profile Field  | Keycloak Attribute     | Notes                        |
|-------------------|-------------------------|------------------------|------------------------------|
| `open_id`         | broker user ID          | `feishu_open_id`       | Stable user identifier       |
| `union_id`        | —                       | `feishu_union_id`      | Cross-app user identifier    |
| `name`            | firstName, username     | `feishu_name`          | Chinese display name         |
| `en_name`         | lastName                | `feishu_en_name`       | English name (or Chinese if same) |
| `email`           | email (if non-blank)    | `feishu_email`         | May be `""` — skipped if empty |
| `mobile`          | —                       | `feishu_mobile`        | Phone number                 |
| `avatar_big`      | avatar (preferred)      | `feishu_avatar_big`    | 640×640                      |
| `avatar_middle`   | avatar (fallback)       | `feishu_avatar_middle` | 240×240                      |
| `avatar_thumb`    | avatar (fallback)       | `feishu_avatar_thumb`  | 72×72                        |
| `avatar_url`      | avatar (last fallback)  | `feishu_avatar_url`    | 72×72                        |
| `tenant_key`      | —                       | `feishu_tenant_key`    | Tenant identifier            |
| `user_id`         | —                       | `feishu_user_id`       | Employee ID (requires extra scope) |
| `sub`             | —                       | `feishu_sub`           | Subject (may not be present) |
| `nickname`        | —                       | `feishu_nickname`      | (usually not returned)       |

**Avatar priority**: `avatar_big` → `avatar_middle` → `avatar_thumb` → `avatar_url`

## OAuth2 Flow Details

```
User → Keycloak Login → clicks "Feishu"
       ↓
GET <auth-endpoint>?app_id=...&redirect_uri=...&response_type=code&scope=user_info
       ↓ (user authorizes)
POST <token-endpoint>  {app_id, app_secret, grant_type, code}
       ↓
GET  <user-info-endpoint>  Bearer: access_token
       ↓
Unwrap {code, msg, data}, parse all fields
       ↓
Map to Keycloak user attributes (prefix: feishu_)
       ↓
User logged in
```

Key differences from a standard OIDC IdP:

| Aspect | Standard OIDC | Feishu |
|--------|--------------|--------|
| Auth param | `client_id` | `app_id` |
| Token auth | Basic Auth / POST body | JSON body with `app_id` + `app_secret` |
| Token response | `access_token` at root | `{"code":0,"data":{"access_token":"..."}}` |
| User info envelope | flat JSON | `{"code":0,"data":{...},"msg":"ok"}` |

## Common Scenarios

### International (Larksuite) Tenants

Change the three endpoint URLs from `open.feishu.cn` to `open.larksuite.com`:

| Setting | Value |
|---------|-------|
| Authorization endpoint URL | `https://open.larksuite.com/open-apis/authen/v1/authorize` |
| Token endpoint URL | `https://open.larksuite.com/open-apis/oauth/v3/token` |
| User info endpoint URL | `https://open.larksuite.com/open-apis/authen/v1/user_info` |

### Custom Proxy / API Gateway

If you route Feishu API traffic through an internal gateway, replace
`open.feishu.cn` with your gateway hostname in all three endpoint URLs.

## Project Structure

```
keycloak-feishu/
├── pom.xml
├── README.md
├── .github/workflows/release.yml
├── src/
│   ├── main/
│   │   ├── java/com/keycloak/feishu/
│   │   │   ├── FeishuIdentityProvider.java        # OAuth2 flow logic
│   │   │   ├── FeishuIdentityProviderConfig.java   # Configuration model
│   │   │   ├── FeishuIdentityProviderFactory.java  # SPI factory
│   │   │   └── mapper/
│   │   │       └── FeishuUserAttributeMapper.java  # Attribute mapper
│   │   └── resources/META-INF/services/
│   │       └── org.keycloak.broker.provider.IdentityProviderFactory
│   └── test/java/com/keycloak/feishu/
│       └── FeishuUserInfoParsingTest.java
```

## License

MIT
