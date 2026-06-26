# wiseadmin/wise-jwt

> WiseAdmin JWT 令牌管理包 — 签发/校验/吊销/续签，支持 HMAC/RSA/ECDSA/EdDSA，生产级方案

[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D8.1-blue)](https://www.php.net)
[![ThinkPHP](https://img.shields.io/badge/ThinkPHP-%5E6.0%20%7C%7C%20%5E8.0-green)](https://www.thinkphp.cn)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)
[![Packagist](https://img.shields.io/badge/packagist-wiseadmin%2Fwise--jwt-orange)](https://packagist.org/packages/wiseadmin/wise-jwt)

---

## 特性

| 模块 | 说明 |
|------|------|
| **10 种签名算法** | HS256/384/512、RS256/384/512、ES256/384/512、EdDSA |
| **零外部依赖** | 纯 PHP 实现全部算法，不依赖第三方 JWT 库 |
| **黑名单吊销** | Cache / Redis 双驱动黑名单，吊销即生效 |
| **自动续签** | `refresh_ttl` 窗口内自动签发新 Token |
| **多提取器** | Bearer Header / Cookie / Query 参数，支持链式组合 |
| **声明校验** | 过期/生效/签发者/受众四类可配置校验规则 |
| **Auth 中间件** | `JwtAuth` 中间件，路由级别鉴权 |
| **流式签发** | `Builder` 构建器，语义化签发 |
| **事件驱动** | 签发/解析/吊销/无效全生命周事件 |

---

## 安装

```bash
composer require wiseadmin/wise-jwt
```

---

## 配置

发布配置文件：

```bash
php think wise:jwt:publish
```

配置文件 `config/wise-jwt.php`：

```php
return [
    // 签名算法
    'algorithm' => 'HS256',

    // HMAC 密钥（HS256/384/512）
    'secret' => env('JWT_SECRET', 'your-secret-key-change-me'),

    // RSA 私钥/公钥路径（RS256/384/512）
    'private_key' => '',
    'public_key'  => '',

    // 签发者标识
    'issuer' => 'wise-jwt',

    // Token 有效期（秒），默认 2 小时
    'ttl' => 7200,

    // 续签窗口（秒），剩余有效期 < 此值时自动续签
    'refresh_ttl' => 1800,

    // 受众（可选）
    'audience' => null,

    // 时间容差（秒），用于处理时钟偏差
    'leeway' => 0,

    // 声明校验开关
    'validation' => [
        'check_expiration'  => true,    // 检查过期
        'check_not_before'  => true,    // 检查生效时间
        'check_issuer'      => true,    // 检查签发者
        'check_audience'    => false,   // 检查受众
    ],

    // 黑名单配置
    'blacklist' => [
        'enable' => true,
        'driver' => 'cache',            // cache / redis
        'prefix' => 'jwt:blacklist:',
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
// → eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.xxx.yyy

// 附带自定义声明
$token = Jwt::issue($userId, [
    'role'   => 'admin',
    'dept_id' => 5,
]);

// 指定有效期（覆盖默认 ttl）
$token = Jwt::issue($userId, ['role' => 'admin'], 3600);  // 1小时
```

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

### 4. 续签 Token

```php
// 自动续签：在 refresh_ttl 窗口内，旧 Token 被吊销，返回新 Token
try {
    $newToken = Jwt::refresh($oldToken);
} catch (\Exception $e) {
    // 超出续签窗口，需重新登录
}
```

### 5. 吊销 Token（加入黑名单）

```php
Jwt::revoke($token);

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

中间件自动从 Bearer Header 提取 Token，校验通过后将 payload 注入请求上下文：

```php
class UserController
{
    public function profile()
    {
        // 在控制器中获取 payload 的两种方式
        $payload = request()->jwtPayload;
        // 或
        $userId = request()->jwtPayload['sub'];
    }
}
```

### 7. 自定义提取器

默认使用 `BearerHeaderExtractor`（从 `Authorization: Bearer xxx` 提取），也支持链式组合：

```php
// 在配置中定义提取器链
// 优先从 Header 提取，其次 Cookie，最后 Query
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

## 目录结构

```
wise-jwt/
├── composer.json
├── config/
│   └── wise-jwt.php                # 配置文件
└── src/
    ├── Service.php                 # 服务提供者
    ├── Jwt.php                     # JWT 核心类
    ├── Builder.php                 # 流式签发构建器
    ├── Payload.php                 # Payload 值对象
    ├── helper.php                  # 助手函数
    ├── blacklist/
    │   ├── BlacklistInterface.php
    │   ├── AbstractBlacklist.php
    │   ├── CacheBlacklist.php
    │   └── RedisBlacklist.php
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
    │   └── BlacklistedException.php
    ├── extractor/
    │   ├── TokenExtractor.php
    │   ├── BearerHeaderExtractor.php
    │   ├── CookieExtractor.php
    │   ├── QueryExtractor.php
    │   └── ChainExtractor.php
    ├── facade/
    │   └── Jwt.php                 # Facade
    ├── middleware/
    │   └── JwtAuth.php             # 认证中间件
    ├── signer/
    │   ├── SignerInterface.php
    │   ├── HS256Signer.php
    │   ├── HS384Signer.php
    │   ├── HS512Signer.php
    │   ├── RS256Signer.php
    │   ├── RS384Signer.php
    │   ├── RS512Signer.php
    │   ├── ES256Signer.php
    │   ├── ES384Signer.php
    │   ├── ES512Signer.php
    │   └── EdDSASigner.php
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

## License

MIT
