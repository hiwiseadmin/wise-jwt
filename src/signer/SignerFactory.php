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
 *
 * 密钥加载优先级：
 * 1. 直接配置值（secret / private_key / public_key）
 * 2. Base64 编码值（secret_base64 / private_key_base64 / public_key_base64）
 * 3. 文件路径（secret_file / private_key_file / public_key_file）
 */
class SignerFactory
{
    /**
     * 根据算法名和配置创建签名器实例
     *
     * @param string $alg    算法名（大小写不敏感）
     * @param array  $config 配置数组，支持以下密钥传递方式：
     *                        - 'secret' / 'private_key' / 'public_key' — 直接内容（HMAC 密钥 或 PEM 内容）
     *                        - 'secret_base64' / 'private_key_base64' / 'public_key_base64' — Base64 编码内容
     *                        - 'secret_file' / 'private_key_file' / 'public_key_file' — 文件路径
     * @return SignerInterface
     * @throws JwtException 当算法不支持时
     */
    public static function create(string $alg, array $config): SignerInterface
    {
        $alg = strtoupper($alg);

        return match ($alg) {
            'HS256' => new HS256Signer(self::resolveKey($config, 'secret')),
            'HS384' => new HS384Signer(self::resolveKey($config, 'secret')),
            'HS512' => new HS512Signer(self::resolveKey($config, 'secret')),
            'RS256' => new RS256Signer(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            'RS384' => new RS384Signer(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            'RS512' => new RS512Signer(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            'ES256' => new ES256Signer(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            'ES384' => new ES384Signer(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            'ES512' => new ES512Signer(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            'EDDSA' => new EdDSASigner(
                self::resolveKey($config, 'private_key'), self::resolveKey($config, 'public_key')),
            default => throw new JwtException("不支持的算法: {$alg}"),
        };
    }

    /**
     * 按优先级解析密钥值
     *
     * 1. 直接值（$config[$key]）
     * 2. Base64 编码值（$config[$key . '_base64']）
     * 3. 文件路径（$config[$key . '_file'] — 自动读取文件内容）
     */
    protected static function resolveKey(array $config, string $key): string
    {
        // 1. 直接值
        $value = (string) ($config[$key] ?? '');
        if ($value !== '') {
            return $value;
        }

        // 2. Base64 编码值
        $base64Value = (string) ($config[$key . '_base64'] ?? '');
        if ($base64Value !== '') {
            $decoded = base64_decode($base64Value, true);
            if ($decoded === false) {
                throw new JwtException("{$key}_base64 解码失败，请确认 Base64 编码正确");
            }
            return $decoded;
        }

        // 3. 文件路径
        $filePath = (string) ($config[$key . '_file'] ?? '');
        if ($filePath !== '') {
            if (!file_exists($filePath)) {
                throw new JwtException("{$key}_file 文件不存在: {$filePath}");
            }
            $content = file_get_contents($filePath);
            if ($content === false || trim($content) === '') {
                throw new JwtException("{$key}_file 内容为空: {$filePath}");
            }
            return $content;
        }

        return '';
    }
}
