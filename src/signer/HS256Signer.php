<?php
declare(strict_types=1);

namespace wise\jwt\signer;

/**
 * HS256 签名器 — HMAC-SHA256
 */
class HS256Signer extends AbstractSigner
{
    public const ALG = 'HS256';

    public function __construct(protected string $secret)
    {
        if ($secret === '') {
            throw new \wise\jwt\exception\JwtException('HMAC 密钥不能为空，请设置 JWT_SECRET 环境变量');
        }
    }

    public function algorithm(): string { return self::ALG; }

    public function sign(string $headerB64, string $payloadB64): string
    {
        return hash_hmac('sha256', $headerB64 . '.' . $payloadB64, $this->secret, true);
    }

    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool
    {
        $expected = $this->sign($headerB64, $payloadB64);
        return hash_equals($expected, $signatureB64);
    }
}
