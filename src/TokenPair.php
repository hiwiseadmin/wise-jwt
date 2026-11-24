<?php
declare(strict_types=1);

namespace wise\jwt;

/**
 * Token 对值对象 — 封装 access_token + refresh_token 双令牌响应
 *
 * 用法：
 * $pair = $jwt->issuePair('user-123');
 * echo $pair->accessToken;   // Access Token 字符串
 * echo $pair->refreshToken;  // Refresh Token 字符串
 * json($pair->toArray());    // 标准 JSON 响应
 */
class TokenPair
{
    /**
     * @param string $accessToken      Access Token
     * @param string $refreshToken     Refresh Token
     * @param string $tokenType        令牌类型，默认 Bearer
     * @param int    $expiresIn        Access Token 过期时间（秒）
     * @param int    $refreshExpiresIn Refresh Token 过期时间（秒）
     */
    public function __construct(
        public readonly string $accessToken,
        public readonly string $refreshToken,
        public readonly string $tokenType = 'Bearer',
        public readonly int $expiresIn = 7200,
        public readonly int $refreshExpiresIn = 2592000
    ) {}

    /**
     * 转为标准 JSON 响应数组
     *
     * @return array{access_token: string, refresh_token: string, token_type: string, expires_in: int, refresh_expires_in: int}
     */
    public function toArray(): array
    {
        return [
            'access_token'       => $this->accessToken,
            'refresh_token'      => $this->refreshToken,
            'token_type'         => $this->tokenType,
            'expires_in'         => $this->expiresIn,
            'refresh_expires_in' => $this->refreshExpiresIn,
        ];
    }
}
