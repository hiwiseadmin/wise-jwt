<?php
declare(strict_types=1);

namespace wise\jwt\facade;

use think\Facade;

/**
 * JWT 门面
 *
 * @method static string           issue(string|int $subject, array $claims = [], ?int $ttl = null) 签发 JWT
 * @method static \wise\jwt\TokenPair issuePair(string|int $subject, array $claims = [], ?int $accessTtl = null, ?int $refreshTtl = null) 签发 Token 对
 * @method static \wise\jwt\TokenPair refreshAccessToken(string $refreshToken, array $customClaims = []) 用 Refresh Token 换取新 Token 对
 * @method static bool             revokeRefreshToken(string $refreshToken)                         吊销 Refresh Token
 * @method static array            parse(string $token)                                             解析并校验 JWT
 * @method static array|null       tryParse(string $token)                                           安全解析（失败返回 null）
 * @method static array|null       decode(string $token)                                             仅解码 payload（不验签）
 * @method static array|null       decodeHeader(string $token)                                       仅解码 header（不验签）
 * @method static array|null       decodeFull(string $token)                                         解码 header + payload（不验签）
 * @method static int              ttlOf(array $payload)                                             距过期时间（秒）
 * @method static bool             shouldRefresh(array $payload)                                     是否需要续签
 * @method static string           refresh(string $token)                                            续签令牌
 * @method static bool             revoke(string $token)                                             吊销令牌
 * @method static int              revokeMany(array $tokens)                                         批量吊销令牌
 * @method static bool             isRevoked(string $jti)                                            检查吊销
 * @method static bool             revokeByJti(string $jti, int $expiresAt = 0)                       按 jti 直接吊销（expiresAt 非法时回退为 30 天后）
 * @method static int              revokeAllBySubject(string $subject)                               全局失效：撤销用户所有令牌
 * @method static int              getVersion(string $subject)                                       获取用户令牌版本号
 * @method static \wise\jwt\Builder builder()                                                       获取流式签发构建器
 * @method static string           getAlgorithm()                                                    获取算法
 * @method static string           getIssuer()                                                       获取签发者
 * @method static int              getTtl()                                                          获取有效期
 * @method static int              getRefreshTokenTtl()                                              获取 Refresh Token 有效期
 * @method static \wise\jwt\fingerprint\TokenFingerprinter|null getFingerprinter()                  获取指纹生成器
 * @method static bool             isGlobalRevokeEnabled()                                           全局失效是否启用
 */
class Jwt extends Facade
{
    protected static function getFacadeClass(): string
    {
        return \wise\jwt\Jwt::class;
    }
}
