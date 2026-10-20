# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed
- `DatabaseBlacklist` 改用 `Db::name()` 访问（原 `Db::table('jwt_blacklist')` 不会拼表前缀），
  与迁移建出的 `ws_jwt_blacklist` 落在同一张表上。此前 database 驱动在带 `ws_` 前缀的库中会因表不存在而吊销失败。
- `JwkConverter::jwkToPublicKey()` 修复 RSA/EC 的 JWK → PEM 转换。原实现存在两处独立缺陷：
  `packRsaKey()` 字段顺序错误、长度字段少算且缺少 `RSAPublicKey` 外层 `SEQUENCE`，
  `packEcKey()` 硬编码 P-256 的长度并重复编码 BIT STRING 长度，产出的 ASN.1 无法被 OpenSSL 解析；
  同时 `rsaFromJwk()` / `ecFromJwk()` 对**公钥**误用 `openssl_pkey_export()`（该函数仅导出私钥，
  传入公钥返回 `false` 且不写出 `$output`）。两处叠加导致该 API 对 RSA/EC 恒失败，现已改为按
  SubjectPublicKeyInfo 构造并从 `openssl_pkey_get_details()` 取 PEM。
- `JwkConverter::publicKeyToJwk()` 对非法 PEM 改抛 `JwtException`（原先把 `false` 传给
  `openssl_pkey_get_details()`，抛出的是 `TypeError`，与 `@throws JwtException` 契约不符）。
- `refresh_token` 配置节接线到引擎：`JwtGuardManager::guard()` 现将 `refresh_token.enable` /
  `refresh_token.fingerprint` 传入 `Jwt` 的 `refreshTokenRotation` / `refreshTokenFingerprint`。
  此前这两个键从未被读取，配置后 Rotation 与换票指纹绑定均不生效（安全开关静默失效）。
- `Builder::issue()` 将 `exp` / `jti` 纳入标准声明后置保护：`->claim('exp'|'jti')` 不再能绕过
  `->ttl()` 与 jti 生成，与 `Jwt::issue()` 的加固策略对齐。
- 新增 `tests/JwkConverterTest.php`：覆盖 RSA / EC（P-256/384/521）JWK 往返一致性与异常契约。

### Changed
- `ExtPoint('jwt.provider')` 的注册实现支持可选守卫名：传入 guard 名且该 guard 已在 `wise-jwt.guards`
  中配置时返回该守卫专属引擎（各自密钥 / issuer / audience）；未配置或未传参时返回默认引擎
  （与历史行为一致，避免打断「鉴权守卫名 ≠ JWT 守卫名」的既有用法）。配套新增
  `JwtGuardManager::hasGuard(string $name): bool`。
- `ExtPoint('jwt.provider')` 对**未在 `wise-jwt.guards` 中登记**的守卫名仍回退默认引擎，但改为记录
  一次性 `ContextualLogger::warning`（含 guard 名、回退目标与已登记的守卫列表）。原实现的静默回退
  会让 `TokenGuard('api')` 复用 app 守卫的密钥 / issuer 验签，配置疏漏时跨守卫令牌互认且无从察觉。
- **行为变更（BREAKING）** EdDSA 的 `alg` 按 RFC 8037 写出混合大小写 `EdDSA`（原统一 `strtoupper()`
  写出 `EDDSA`，标准 JWT 库无法识别，互操作失败）。
- **行为变更（BREAKING）** `AudienceRule` 在启用 `validation.check_audience` 后，对缺失 `aud` 声明的
  令牌改为 fail-closed 拒绝，与 `ExpirationRule`（缺 `exp` 视为过期）、`Jwt::checkVersion()`（缺 `ver`
  视为失效）的基线保持一致；如需兼容无 `aud` 的历史令牌请自行注册自定义规则。
- **表结构变更（不做兼容迁移）** `jwt_blacklist`：`expires_at` 改为无符号 `INT`（原为有符号 `INT`，存在 2038 溢出风险），
  `create_time` 由整型时间戳改为 `DATETIME`（与框架时间字段约定一致）。存量库需手工 `ALTER TABLE`。
- `Jwt::revokeByJti()` 增加 `expiresAt` 合法性校验：超出 `(now, 4294967295]` 的入参
  （如误传毫秒时间戳、已过去的时刻）回退为默认 30 天并记录告警；`0`（未显式传入）仍走默认值。

## [1.0.1] - 2026-09-19

### Security
- **BREAKING** `JwtAuth` 中间件拒绝 `typ=refresh` 的令牌：Refresh Token 不得作为 Access Token 访问业务接口。
- `Jwt::checkVersion()` 改为 fail-closed：缺少 `ver` 声明（含 `global_revoke` 开启前签发的历史令牌）或版本号不等于当前版本一律拒绝。
- `ExpirationRule` 改为 fail-closed：缺少 `exp` 声明的令牌视为过期。
- `Jwt::revoke()` / `revokeRefreshToken()` / `revokeMany()` 依据黑名单写入结果返回，避免缓存故障时的「假吊销」。
- Refresh Token Rotation 改用原子占位 `BlacklistInterface::reserve()`，消除检查-写入的 TOCTOU 并发重放窗口。
- `Jwt::issue()` / `Builder::issue()` 标准声明后置，防止自定义 claims 覆盖 `sub` / `iss` / `exp` / `jti`。
- 默认 Token 提取器收紧为 `['bearer']`（`query` 存在令牌泄漏风险、`cookie` 需配套 CSRF 防护）。

### Fixed
- ECDSA（ES256/384/512）raw 签名长度修正为 RFC 7515 规定的 64/96/132 字节：`derToRaw()` 剥离 DER 符号前缀字节并归一到定长分量，`rawToDer()` 支持 DER 长格式长度（ES512 总长 136 ≥ 0x80 时不再产生非法编码）。
- `DatabaseBlacklist::add()` 修正异常类型（`think\db\exception\PDOException`）并从 `getData()` 读取 SQLSTATE，恢复重复 jti 的更新时间分支。
- `Jwt::refresh()` 强制续签窗口（`should_refresh`），超出窗口不再允许无限续期。
- `JwtGuardManager::buildValidatorFromConfig()` 生效 `validation.check_issued_at` 配置开关。
- `JwtAuth` 中间件不再把路由级 Guard/提取器写回实例属性，避免 Swoole/Workerman 常驻运行时跨请求污染。
- `Builder::issuePair()` 的 `rotation()` / `refreshTokenFingerprint()` / `audience()` 覆盖改为作用于 Jwt 克隆体，不再污染被 Facade/容器缓存的共享实例。
- `wise:jwt:blacklist --flush` 对不支持枚举的 Cache 驱动显式报错，不再静默返回「已清空 0 条」。
- 指纹上下文为空时记录告警日志。

### Changed
- `BlacklistInterface` 新增 `reserve(string $jti, int $expiresAt): bool`，自定义黑名单驱动需同步实现。
- `JwtAuth::getExtractor()` 改为按「提取器名组合」缓存提取器链。
- 移除 PHP 8.0+ 已弃用的 `openssl_free_key()` 调用。
- 文档修正：`TokenPair` 属性访问、路由级中间件变参写法、JWK 支持范围（RSA/EC）、许可证（Apache-2.0）、目录结构。

## [1.0.0] - 2024-01-01

### Added
- Initial release

[1.0.1]: https://github.com/wiseadmin/wise-jwt/releases/tag/v1.0.1
[1.0.0]: https://github.com/wiseadmin/wise-jwt/releases/tag/v1.0.0
