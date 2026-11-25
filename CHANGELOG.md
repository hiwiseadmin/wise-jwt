# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.3] - 2026-11-25

### Fixed
- 修复黑名单表名未带前缀、RSA/EC JWK 转换失败、刷新令牌配置未生效、标准声明可被覆盖等问题。
- 非法 PEM 改抛 `JwtException`；`revokeByJti()` 对非法过期时间回退默认值并记录告警。

### Changed
- JWT 引擎支持按守卫选择密钥/issuer/audience，未登记的守卫回退默认引擎并记录告警。
- EdDSA 按标准写出 `EdDSA`；启用 aud 校验后缺失 `aud` 的令牌被拒绝。
- 黑名单表 `expires_at` / `create_time` 列类型调整，存量库需手工 ALTER。

## [1.0.1] - 2026-09-19

### Security
- Refresh Token 不得作为 Access Token；版本、过期声明缺失时 fail-closed；吊销结果不再假成功。
- Refresh Rotation 改为原子占位，消除并发重放窗口；默认令牌提取收紧为 bearer。

### Fixed
- 修正 ECDSA 原始签名长度、续签窗口、常驻运行时跨请求污染等问题。

### Changed
- `BlacklistInterface` 新增 `reserve()`，自定义驱动需实现。

## [1.0.0] - 2024-01-01

- Initial release

[1.0.1]: https://github.com/hiwiseadmin/wise-jwt/releases/tag/v1.0.1
[1.0.0]: https://github.com/hiwiseadmin/wise-jwt/releases/tag/v1.0.0

[Unreleased]: https://github.com/hiwiseadmin/wise-jwt/compare/v1.0.3...HEAD
[1.0.3]: https://github.com/hiwiseadmin/wise-jwt/releases/tag/v1.0.3
