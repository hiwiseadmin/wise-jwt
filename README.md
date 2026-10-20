# wiseadmin/wise-jwt

> WiseAdmin JWT 令牌管理包 — 签发/校验/吊销/续签，支持 HMAC/RSA/ECDSA/EdDSA，生产级方案

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.1-blue)](https://www.php.net)
[![ThinkPHP](https://img.shields.io/badge/ThinkPHP-%5E6.0%20%7C%7C%20%5E8.0-green)](https://www.thinkphp.cn)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen)](LICENSE)
[![Packagist](https://img.shields.io/badge/packagist-wiseadmin%2Fwise--jwt-orange)](https://packagist.org/packages/wiseadmin/wise-jwt)

---

## 特性

| 模块 | 说明 |
|------|------|
| **10 种签名算法** | HS256/384/512、RS256/384/512、ES256/384/512、EdDSA（EdDSA 需 `ext-sodium`） |
| **零外部依赖** | 纯 PHP 实现全部算法，不依赖第三方 JWT 库（仅需 `ext-openssl`） |
| **双令牌模式** | Access Token + Refresh Token；Rotation 原子占位防并发重放，Refresh Token 不能当 Access Token 用 |
| **全局令牌失效** | Token Version 机制，一键撤销用户所有令牌（缺 `ver` 的历史令牌会被拒绝） |
| **黑名单吊销** | Cache / Redis / Database 三驱动；Cache 驱动按 TTL 自动过期（不支持 flush） |
| **设备指纹绑定** | UA / IP / 设备特征三级安全强度 |
| **频率限制** | 内置 Rate Limiter，防暴力破解 |
| **自动续签** | `refresh_ttl` 窗口内自动签发新 Token（窗口外 `refresh()` 直接拒绝） |
| **密钥轮换** | 多密钥 Kid 识别 + 主备密钥无缝轮换 |
| **多 Guard** | 按场景独立配置密钥/算法/有效期 |
| **多提取器** | 默认仅 Bearer Header；Cookie / Query 需显式开启，支持路由级自定义 |
| **声明校验** | 过期/生效/签发时间/签发者/受众 + 自定义规则注册 |
| **JWK 转换** | PEM ↔ JWK 双向转换（RSA / EC），对接 OIDC 身份系统 |
| **Auth 中间件** | `JwtAuth` 中间件，路由级别鉴权（自动拒绝 Refresh Token） |
| **流式签发** | `Builder` 构建器，语义化签发 |
| **事件驱动** | 签发/解析/吊销/无效全生命周期事件（需宿主自行 `Event::listen()` 注册，包内无默认监听器） |
| **密钥多样化** | 支持直接值/Base64/文件路径三种密钥传递方式 |

---

## 安装

```bash
composer require wiseadmin/wise-jwt
```

---

## 配置

配置文件 `config/wise-jwt.php`（下列为常用项，完整默认值以包内 `config/wise-jwt.php` 为准）：

```php
return [
    // ── 默认 Guard 与签名算法 ──
    'default'   => 'app',
    'algorithm' => 'HS256',                 // HS256/384/512 | RS256/384/512 | ES256/384/512 | EdDSA

    // ── HMAC 密钥（优先级：secret > secret_base64 > secret_file）──
    'secret'        => env('JWT_SECRET', ''),
    'secret_base64' => env('JWT_SECRET_BASE64', ''),
    'secret_file'   => env('JWT_SECRET_FILE', ''),

    // ── 非对称密钥（优先级：直接值 > _base64 > _file）──
    'private_key'        => env('JWT_PRIVATE_KEY', ''),
    'private_key_base64' => env('JWT_PRIVATE_KEY_BASE64', ''),
    'private_key_file'   => env('JWT_PRIVATE_KEY_FILE', ''),
    'public_key'         => env('JWT_PUBLIC_KEY', ''),
    'public_key_base64'  => env('JWT_PUBLIC_KEY_BASE64', ''),
    'public_key_file'    => env('JWT_PUBLIC_KEY_FILE', ''),

    // ── 签发参数 ──
    'issuer'      => 'wiseadmin',
    'audience'    => '',
    'ttl'         => 7200,                  // Access Token 有效期（秒）
    'refresh_ttl' => 1800,                  // 续签窗口：剩余有效期 < 此值才允许 refresh()
    'leeway'      => 0,                     // 时钟容差（秒）

    // ── 黑名单（cache / redis / database）──
    'blacklist' => [
        'enable'   => true,
        'driver'   => 'cache',
        'prefix'   => 'jwt:blacklist:',
        'db_table' => 'jwt_blacklist',
    ],

    // ── Refresh Token 双令牌模式 ──
    'refresh_token' => [
        'enable'      => true,
        'ttl'         => 2592000,           // 30 天
        'fingerprint' => false,
    ],

    // ── 设备指纹绑定 ──
    'fingerprint' => [
        'enable' => false,
        'level'  => 'MEDIUM',               // LOW(UA) | MEDIUM(UA+IP) | HIGH(UA+IP+Lang+Encoding)
        'strict' => false,                  // true: 缺少 fph 声明的令牌一律拒绝
    ],

    // ── 频率限制 ──
    'throttle' => [
        'enable'        => false,
        'max_attempts'  => 5,
        'decay_seconds' => 60,
        'key_type'      => 'ip',            // ip | route | ip_route
        'prefix'        => 'jwt:throttle:',
    ],

    // ── 全局令牌失效（Token Version）──
    'global_revoke' => [
        'enable' => false,                  // 开启后，历史令牌（无 ver 声明）会被拒绝
    ],

    // ── 版本号持久化（防 cache:clear 导致已吊销令牌复活）──
    'version_persistence' => [
        'enable'    => true,
        'file_path' => '',                  // 留空 = runtime/wise-jwt/version/
    ],

    // ── 密钥轮换（首个 active 密钥用于签名，其余用于验签）──
    'keys' => [],

    // ── Token 提取（默认仅 bearer）──
    'token' => [
        'extractors'  => ['bearer'],        // 可追加 'cookie' / 'query'（注意 CSRF 与 URL 泄漏风险）
        'header_name' => 'Authorization',
        'cookie_name' => 'wise_token',
        'query_name'  => 'token',
    ],

    // ── 多 Guard ──
    'guards' => [
        'app' => [
            'algorithm'         => 'HS256',
            'secret'            => '',      // 留空自动继承顶层 secret
            'issuer'            => 'wiseadmin-app',
            'ttl'               => 7200,
            'refresh_ttl'       => 1800,
            'refresh_token_ttl' => 2592000,
        ],
        'admin' => [
            'algorithm'         => 'HS256',
            'secret'            => env('JWT_ADMIN_SECRET', ''),
            'issuer'            => 'wiseadmin-admin',
            'ttl'               => 3600,
            'refresh_ttl'       => 900,
            'refresh_token_ttl' => 1209600,
        ],
    ],

    // ── 自动续签 ──
    'auto_refresh' => true,

    // ── 校验规则开关 ──
    'validation' => [
        'check_expiration' => true,
        'check_not_before' => true,
        'check_issued_at'  => true,
        'check_issuer'     => true,
        'check_audience'   => false,
    ],
];
```

---

## 使用指南

### 1. 签发 Token

```php
use wise\jwt\facade\Jwt;

// 基本签发
$token = Jwt::issue($userId);
// → eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxx.yyy   (header = {"alg":"HS256","typ":"JWT"})

// 附带自定义声明
$token = Jwt::issue($userId, [
    'role'   => 'admin',
    'dept_id' => 5,
]);

// 指定有效期（覆盖默认 ttl）
$token = Jwt::issue($userId, ['role' => 'admin'], 3600);  // 1小时
```

> 注意：`iss` / `sub` / `iat` / `nbf` / `exp` / `jti` 属于标准声明，**不会被 `$claims` 覆盖**
> （`sub` 恒取 `$subject`，`exp` 由 `$ttl` 决定）。请勿把请求参数整体当作 `$claims` 传入。

### 2. 流式签发（Builder）

```php
$token = app('jwt')->builder()
    ->subject($userId)
    ->claim('role', 'admin')
    ->claim('dept_id', 5)
    ->ttl(3600)
    ->issuer('my-app')
    ->audience('mobile')
    ->issue();
```

### 3. 解析与校验 Token

```php
// 完整校验（验签 + 过期 + 黑名单 + 声明）
try {
    $payload = Jwt::parse($token);
    // 返回: ['sub' => 1, 'role' => 'admin', 'exp' => 1718256000, ...]
    echo $payload['sub'];   // 用户ID
    echo $payload['role'];  // 自定义声明
} catch (\wise\jwt\exception\TokenExpiredException $e) {
    // Token 已过期
} catch (\wise\jwt\exception\SignatureInvalidException $e) {
    // 签名无效
} catch (\wise\jwt\exception\BlacklistedException $e) {
    // 已被吊销
}

// 安全解析（失败返回 null，不抛异常）
$payload = Jwt::tryParse($token);
if ($payload === null) {
    // Token 无效
}
```

> `parse()` 只做「签名 + 声明 + 黑名单 + 版本」校验，**不区分令牌类型**：
> Refresh Token 同样能通过 `parse()`（`refreshAccessToken()` 依赖这一点）。
> 因此**不要**用 `parse()` 校验业务接口的来访令牌——请使用 `JwtAuth` 中间件，
> 它会额外拒绝 `typ=refresh` 的令牌。

### 4. 续签 Token

```php
// 续签：仅在 refresh_ttl 窗口内（剩余有效期 < refresh_ttl）允许，
// 旧 Token 被吊销后返回新 Token；超出窗口会抛 TokenInvalidException
try {
    $newToken = Jwt::refresh($oldAccessToken);
} catch (\wise\jwt\exception\TokenInvalidException $e) {
    // 未进入续签窗口 / 令牌已失效，需重新登录
}
```

### 5. 吊销 Token（加入黑名单）

```php
// 返回 bool：黑名单写入失败时返回 false（不会「假成功」）
if (!Jwt::revoke($token)) {
    // 吊销失败，需告警：令牌仍可能有效
}

// 检查是否已吊销
$revoked = Jwt::isRevoked($jti);
```

### 6. 中间件鉴权

```php
// route/api.php
use wise\jwt\middleware\JwtAuth;

Route::group('api', function () {
    Route::get('profile', 'api.User/profile');
    Route::post('order', 'api.Order/create');
})->middleware(JwtAuth::class);
```

中间件自动从 Bearer Header 提取 Token，校验通过后注入两层上下文：
`$request->jwt_payload` / `$request->jwt_token`（请求级属性）与 `RequestContext`
（等价于 `jwt_payload` / `jwt_token` / `user_id` / `jwt_sub`，Swoole 等常驻运行时推荐使用）：

```php
class UserController
{
    public function profile()
    {
        // 推荐：RequestContext（FPM / Swoole 行为一致，随请求结束自动清理）
        $payload = \wise\support\context\RequestContext::get('jwt_payload');
        $userId  = \wise\support\context\RequestContext::get('user_id');

        // 兼容：请求级属性（键名是 snake_case 的 jwt_payload）
        $payload = request()->jwt_payload;
        $userId  = request()->jwt_payload['sub'];
        $token   = request()->jwt_token;
    }
}
```

> `request()->jwtPayload`（驼峰）**并不存在**：ThinkPHP 的动态属性按注入时的原始键名存取。
> 中间件还会自动拒绝 `typ=refresh` 的令牌，Refresh Token 无法用于业务接口鉴权。

### 7. 自定义提取器

默认仅使用 `BearerHeaderExtractor`（从 `Authorization: Bearer xxx` 提取）。`cookie` / `query`
因存在 CSRF 与令牌经 URL 泄漏的风险，需显式开启。三种方式：

```php
// 方式1：配置文件（全局生效，推荐）
'token' => [
    'extractors'  => ['bearer', 'cookie', 'query'],  // 按顺序尝试，取第一个非空结果
    'header_name' => 'Authorization',
    'cookie_name' => 'wise_token',
    'query_name'  => 'token',
],
```

```php
// 方式2：路由级覆盖（仅影响该条路由，优先级高于全局配置，见第 12 节）
Route::get('/api/download')->middleware(JwtAuth::class, 'app', 'bearer', 'query');
```

```php
// 方式3：手动组装提取器链（不经过中间件时使用）
use wise\jwt\extractor\ChainExtractor;
use wise\jwt\extractor\BearerHeaderExtractor;
use wise\jwt\extractor\CookieExtractor;
use wise\jwt\extractor\QueryExtractor;

$extractor = new ChainExtractor([
    new BearerHeaderExtractor(),
    new CookieExtractor('access_token'),
    new QueryExtractor('token'),
]);
```

### 8. 事件监听

```php
// app/event.php
return [
    'listen' => [
        \wise\jwt\event\TokenIssued::class => [
            \app\listener\LoginHistory::class,
        ],
        \wise\jwt\event\TokenRevoked::class => [
            \app\listener\LogoutCleanup::class,
        ],
        \wise\jwt\event\TokenInvalid::class => [
            \app\listener\SuspiciousActivity::class,
        ],
    ],
];
```

---

## 算法选择指南

| 算法 | 类型 | 密钥 | 适用场景 |
|------|------|------|----------|
| HS256 | HMAC | 单一共享密钥 | 单体应用、内部服务 |
| HS384 | HMAC | 单一共享密钥 | 更高安全要求 |
| HS512 | HMAC | 单一共享密钥 | 最高 HMAC 强度 |
| RS256 | RSA | 私钥签发 + 公钥校验 | 微服务、跨系统 |
| RS384 | RSA | 私钥签发 + 公钥校验 | 更高安全要求 |
| RS512 | RSA | 私钥签发 + 公钥校验 | 最高 RSA 强度 |
| ES256 | ECDSA | 私钥签发 + 公钥校验 | 移动端（签名短） |
| ES384 | ECDSA | 私钥签发 + 公钥校验 | 更高安全要求 |
| ES512 | ECDSA | 私钥签发 + 公钥校验 | 最高 ECDSA 强度 |
| EdDSA | Ed25519 | 私钥签发 + 公钥校验 | 现代应用，性能最优 |

---

## 高级功能

### 9. 双令牌模式（Access Token + Refresh Token）

```php
use wise\jwt\facade\Jwt;

// 签发 Token 对
$pair = Jwt::issuePair($userId, ['role' => 'user'], 7200, 2592000);
echo $pair->accessToken;   // 短效 Access Token（2h）
echo $pair->refreshToken;  // 长效 Refresh Token（30d）

// 用 Refresh Token 换取新 Token 对（旧 Refresh Token 自动吊销，防重放）
$newPair = Jwt::refreshAccessToken($pair->refreshToken);

// Builder 流式签发（完整参数）
$pair = Jwt::builder()
    ->subject($userId)
    ->accessTtl(7200)
    ->refreshTtl(2592000)
    ->rotation(true)                     // 启用 Rotation
    ->refreshTokenFingerprint(true)      // Refresh Token 绑定设备指纹
    ->audience('mobile-app')
    ->issuePair();
```

### 10. 全局令牌失效（Token Version）

修改密码或检测异常登录后，一键撤销用户所有已签发令牌：

```php
// 升级版本号，所有老令牌立即失效
$newVersion = Jwt::revokeAllBySubject($userId);

// 查看当前版本
$version = Jwt::getVersion($userId);
```

> 需配置 `global_revoke.enable = true` 才生效。版本号使用 Cache + File 双写持久化，
> `cache:clear` 不会丢失。

⚠️ **启用时机很关键**：令牌签发时会写入当时的版本号 `ver`，校验时 `ver` 必须与当前版本
**严格相等**，因此：

- 在开关**开启之前**签发的历史令牌没有 `ver`，开启后会被**直接拒绝**（等价于一次全局登出）；
  请先切换开关，再让客户端重新登录，避免线上大面积 401；
- 若 `version_persistence.enable = false` 且版本文件丢失、Cache 又被清空，版本会归零，
  已吊销令牌将复活。生产环境务必保持文件持久化（或改用 Redis 驱动）。

### 11. 设备指纹绑定

```php
// 配置：wise-jwt.fingerprint
'fingerprint' => [
    'enable' => true,
    'level'  => 'MEDIUM',  // LOW(UA) | MEDIUM(UA+IP) | HIGH(UA+IP+Lang+Encoding)
    'strict' => false,     // true: 未携带 fph 声明的令牌一律拒绝
],
```

> `fph` 与当前请求指纹不一致时**一律拒绝**（与 `strict` 无关）；`strict` 只决定
> 「令牌完全没有 `fph`」时是放行还是拒绝。若请求上下文为空（CLI、无 request 的常驻任务），
> 指纹会退化为固定常量并输出告警日志，此时绑定保护实际失效，请确保签发与校验都发生在
> 带请求上下文的链路上。

### 12. 中间件路由级配置

```php
// 默认 Guard + 默认提取器
Route::get('/api/profile')->middleware(JwtAuth::class);

// Admin Guard（独立密钥/有效期）— 参数以变参形式透传，不可写成 [JwtAuth::class, 'admin']
Route::get('/api/admin')->middleware(JwtAuth::class, 'admin');

// 指定 Guard + 仅 Bearer 提取（禁用 Cookie/Query）
Route::get('/api/admin')->middleware(JwtAuth::class, 'admin', 'bearer');

// 分组写法：外层数组是中间件列表，内层是 [中间件类, 参数数组]
Route::group('api', function () {
    Route::get('download', 'api.File/download');
})->middleware([[JwtAuth::class, ['app', 'bearer', 'query']]]);
```

### 13. 自定义校验规则

```php
use wise\jwt\validator\Validator;
use wise\jwt\validator\RuleInterface;

// 1. 实现自定义规则
class RoleRequiredRule implements RuleInterface
{
    public function validate(array $payload): void
    {
        if (empty($payload['role'])) {
            throw new \wise\jwt\exception\TokenInvalidException('缺少 role 声明');
        }
    }
}

// 2. 在 AppServiceProvider::boot() 中全局注册（需早于 JwtGuardManager 构建 Validator）
Validator::registerRule(new RoleRequiredRule());
// 之后所有经容器 / JwtGuardManager 构建的校验都会执行此规则；
// 若手动 new Validator()，需自行调用 applyRegisteredRules()
```

### 14. JWK 转换

```php
use wise\jwt\signer\JwkConverter;

// PEM → JWK（支持 RSA / EC；暂不支持 Ed25519/OKP）
$jwk = JwkConverter::publicKeyToJwk($pemString, kid: 'key-2024', use: 'sig');
// → ['kty' => 'RSA', 'use' => 'sig', 'kid' => 'key-2024', 'alg' => 'RS256', 'n' => '...', 'e' => 'AQAB']

// JWK → PEM
$pem = JwkConverter::jwkToPublicKey($jwk);
```

### 15. 密钥管理

支持三种密钥传递方式，优先级依次递减（HMAC 用 `secret*`，非对称用 `private_key*` / `public_key*`）：

```env
# 方式1：直接值（PEM 内容 / HMAC 密钥）
JWT_SECRET=my-hmac-secret
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----..."

# 方式2：Base64 编码（适合 CI/CD 环境变量）
JWT_SECRET_BASE64=...
JWT_PRIVATE_KEY_BASE64=LS0tLS1CRUdJTi...（base64 编码）

# 方式3：文件路径
JWT_SECRET_FILE=/etc/secrets/jwt-hmac.key
JWT_PRIVATE_KEY_FILE=/etc/secrets/jwt-private.pem
```

**密钥轮换**：通过顶层 `keys` 配置多把密钥并标记 `kid`——首把 `active` 密钥用于签名，
其余仅用于验签，可实现不停机换钥：

```php
'keys' => [
    ['kid' => '2026-09', 'secret' => env('JWT_SECRET_V2', ''), 'active' => true],
    ['kid' => '2026-03', 'secret' => env('JWT_SECRET_V1', '')],   // 旧密钥仅验签
],
```

### 16. 解码增强

```php
// 仅解码 header（查看算法、kid 等）
$header = Jwt::decodeHeader($token);
// → ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'key-2024']

// 完整解码 header + payload
$both = Jwt::decodeFull($token);
// → ['header' => [...], 'payload' => [...]]
```

---

## 安全最佳实践

1. **必须设置 JWT_SECRET**：生产环境不要使用默认/示例密钥（默认值为空，未配置时直接抛异常）
2. **启用 Global Revoke**：改密/异常登录时调用 `revokeAllBySubject()`（开关切换会使历史令牌失效，见第 10 节）
3. **微服务场景用非对称算法**：RS256/ES256，避免共享 HMAC 密钥
4. **Refresh Token 必须开启 Rotation**：旧 token 一次换票即失效；Rotation 采用原子占位，并发重放同样被拒
5. **Refresh Token 只用于换票**：不要作为业务接口凭据（`JwtAuth` 中间件已自动拒绝 `typ=refresh`）
6. **高敏感 API 启用设备指纹**：`fingerprint.level = HIGH`，并确保链路始终有请求上下文
7. **密钥定期轮换**：通过 `keys` 配置实现无缝轮换
8. **保持默认提取器**：仅用 `bearer`；确需 `cookie` 时须自行补充 CSRF 防护
9. **Redis 驱动**：黑名单与版本号建议使用 Redis，而非 file/cache 驱动

---

## 故障排查

| 现象 | 可能原因 | 解决 |
|------|---------|------|
| `算法不匹配` | 签发和验证用了不同算法 | 检查配置 `algorithm` |
| `签名验证失败` | 密钥不一致 | 确认 `secret`/`private_key` 正确 |
| `令牌已全局失效` | 被 `revokeAllBySubject()`；或刚开启 `global_revoke` 导致历史令牌无 `ver` | 重新登录获取新 Token |
| `未进入续签窗口，不允许续签` | 令牌剩余有效期 ≥ `refresh_ttl` | 在窗口内续签，或调大 `refresh_ttl` |
| `Refresh Token 不能用于接口鉴权` | 用 Refresh Token 调业务接口 | 改用 Access Token（先调 `refreshAccessToken()` 换票） |
| `令牌已过期`（令牌本无 `exp`） | 令牌缺少 `exp` 声明 | 该令牌不合规，重新签发 |
| `频率限制触发` | throttle 太严格 | 调整 `max_attempts` |
| `EdDSA: 不支持的算法` | 缺少 `ext-sodium` | `apt install php-sodium` |
| `HS 算法密钥未配置` | `.env` 未设置 `JWT_SECRET` | 运行 `php think wise:jwt:key:generate` 或手动配置 |
| 已吊销令牌在 `cache:clear` 后复活 | Cache 黑名单被清空 | 改用 Redis/数据库驱动，并开启 `global_revoke` + 版本持久化 |
| `--flush` 提示不支持 | 黑名单驱动为 cache | 改用 redis / database 驱动 |

---

## 目录结构

```
wise-jwt/
├── composer.json
├── config/
│   └── wise-jwt.php                # 配置文件
├── database/
│   └── migrations/                 # jwt_blacklist 表（database 驱动用）
└── src/
    ├── Jwt.php                     # JWT 核心类
    ├── config/
    │   └── JwtSecretCheck.php      # 密钥配置检查（ConfigCheckCollector）
    ├── JwtGuardManager.php         # 多 Guard 管理器
    ├── JwtServiceProvider.php      # ThinkPHP 服务注册
    ├── Builder.php                 # 流式签发构建器
    ├── TokenPair.php               # Token 对值对象
    ├── Payload.php                 # Payload 值对象
    ├── helper.php                  # 助手函数
    ├── blacklist/
    │   ├── BlacklistInterface.php
    │   ├── AbstractBlacklist.php
    │   ├── CacheBlacklist.php
    │   ├── RedisBlacklist.php
    │   └── DatabaseBlacklist.php
    ├── command/
    │   ├── KeyGenerate.php
    │   ├── Decode.php
    │   ├── Revoke.php
    │   └── BlacklistManage.php
    ├── event/
    │   ├── TokenIssuing.php
    │   ├── TokenIssued.php
    │   ├── TokenParsing.php
    │   ├── TokenParsed.php
    │   ├── TokenInvalid.php
    │   └── TokenRevoked.php
    ├── exception/
    │   ├── JwtException.php
    │   ├── TokenExpiredException.php
    │   ├── TokenInvalidException.php
    │   ├── SignatureInvalidException.php
    │   ├── BlacklistedException.php
    │   └── ThrottleException.php
    ├── extractor/
    │   ├── TokenExtractor.php
    │   ├── BearerHeaderExtractor.php
    │   ├── CookieExtractor.php
    │   ├── QueryExtractor.php
    │   └── ChainExtractor.php
    ├── fingerprint/
    │   ├── TokenFingerprinter.php
    │   └── FingerprintRule.php
    ├── throttle/
    │   ├── RateLimiter.php
    │   └── ThrottleException.php
    ├── facade/
    │   └── Jwt.php                 # Facade
    ├── middleware/
    │   └── JwtAuth.php             # 认证中间件
    ├── signer/
    │   ├── SignerInterface.php
    │   ├── SignerFactory.php
    │   ├── AbstractSigner.php
    │   ├── ValidatesKeys.php
    │   ├── EcdsaDerTrait.php       # ECDSA DER ↔ raw(r||s) 转换
    │   ├── HS256Signer.php
    │   ├── ...（HS/RS/ES/EdDSA 全部 10 种）
    │   └── JwkConverter.php        # JWK 转换器（RSA / EC）
    └── validator/
        ├── Validator.php
        ├── RuleInterface.php
        ├── ExpirationRule.php
        ├── NotBeforeRule.php
        ├── IssuedAtRule.php
        ├── IssuerRule.php
        └── AudienceRule.php
```

---

## 依赖关系

- **必需**：`topthink/framework`（^6.0 || ^8.0）、`wiseadmin/wise-support`、`ext-json`、`ext-openssl`
- **可选**：`ext-sodium`（EdDSA）；`ext-redis` 或 `predis/predis`（redis 黑名单驱动）
- **迁移**：包内置 `migrate-path`，执行 `php think migrate:run` 后即可使用 database 黑名单驱动

## 许可证

Apache-2.0（见 [LICENSE](LICENSE) 与 `composer.json`）
