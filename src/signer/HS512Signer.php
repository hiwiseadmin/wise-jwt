<?php
declare(strict_types=1);

namespace wise\jwt\signer;

/**
 * HS512 签名器 — HMAC-SHA512
 */
class HS512Signer extends AbstractSigner
{
    public const ALG = 'HS512';

    public function __construct(protected string $secret)
    {
        if ($secret === '') {
            throw new \wise\jwt\exception\JwtException('HMAC 密钥不能为空，请在 config/wise-jwt.php 中设置 secret，或运行 php think wise:jwt:key:generate 生成');
        }
    }

    public function algorithm(): string { return self::ALG; }

    public function sign(string $headerB64, string $payloadB64): string
    {
        return hash_hmac('sha512', $headerB64 . '.' . $payloadB64, $this->secret, true);
    }

    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool
    {
        $expected = $this->sign($headerB64, $payloadB64);
        return hash_equals($expected, $signatureB64);
    }
}
