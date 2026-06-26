<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\JwtException;

/**
 * 签名器工厂 — 统一的签名器创建入口，消除 Service 和 JwtGuardManager 中的重复代码
 *
 * 支持全部 10 种 JWT 算法：
 * - HMAC: HS256, HS384, HS512
 * - RSA: RS256, RS384, RS512
 * - ECDSA: ES256, ES384, ES512
 * - EdDSA: EdDSA
 */
class SignerFactory
{
    /**
     * 根据算法名和配置创建签名器实例
     *
     * @param string $alg    算法名（大小写不敏感）
     * @param array  $config 配置数组，包含 secret 或 private_key/public_key
     * @return SignerInterface
     * @throws JwtException 当算法不支持时
     */
    public static function create(string $alg, array $config): SignerInterface
    {
        $alg = strtoupper($alg);

        return match ($alg) {
            'HS256' => new HS256Signer((string) ($config['secret'] ?? '')),
            'HS384' => new HS384Signer((string) ($config['secret'] ?? '')),
            'HS512' => new HS512Signer((string) ($config['secret'] ?? '')),
            'RS256' => new RS256Signer(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            'RS384' => new RS384Signer(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            'RS512' => new RS512Signer(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            'ES256' => new ES256Signer(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            'ES384' => new ES384Signer(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            'ES512' => new ES512Signer(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            'EDDSA' => new EdDSASigner(
                (string) ($config['private_key'] ?? ''), (string) ($config['public_key'] ?? '')),
            default => throw new JwtException("不支持的算法: {$alg}"),
        };
    }
}
