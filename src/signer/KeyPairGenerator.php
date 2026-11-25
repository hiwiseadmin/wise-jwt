<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\support\crypto\OpenSslConfig;

/**
 * 密钥 / 密钥对生成器
 *
 * 背景（Windows 与缺少系统 openssl.cnf 的精简环境）：
 * openssl_pkey_export() **不会继承** openssl_pkey_new() 传入的 config；
 * 若导出时不显式再传一次，会报
 *   error:80000003:system library::No such process
 * 并返回 false（第二个参数被置为 null），后续按字符串处理即触发 TypeError。
 *
 * 本类统一遵循「openssl_pkey_new + openssl_pkey_export 都传 OpenSslConfig」的写法，
 * 任一环节失败一律抛 RuntimeException，由命令层转成非 0 退出码（不再「失败也返回 0」）。
 */
final class KeyPairGenerator
{
    /** EC 默认曲线（对应 ES256） */
    public const CURVE_P256 = 'prime256v1';

    private function __construct()
    {
    }

    /**
     * 生成 HMAC 密钥（十六进制字符串）
     *
     * @param int $bytes 随机字节数，默认 32 → 64 位十六进制（HS256 及以上足够）
     */
    public static function hmac(int $bytes = 32): string
    {
        if ($bytes < 16) {
            throw new \RuntimeException("HMAC: 密钥长度不能小于 16 字节，当前: {$bytes}");
        }

        return bin2hex(random_bytes($bytes));
    }

    /**
     * 生成 RSA 密钥对
     *
     * @param int $bits 2048 / 4096
     * @return array{private:string,public:string} PEM 格式
     */
    public static function rsa(int $bits = 2048): array
    {
        return self::asymmetric(
            ['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA],
            'RSA'
        );
    }

    /**
     * 生成 EC（ECDSA）密钥对
     *
     * @param string $curve prime256v1 / secp384r1 / secp521r1
     * @return array{private:string,public:string} PEM 格式
     */
    public static function ec(string $curve = self::CURVE_P256): array
    {
        return self::asymmetric(
            ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve],
            'ECDSA'
        );
    }

    /**
     * 生成 EdDSA（Ed25519）密钥对
     *
     * @return array{private:string,public:string} 十六进制（32 字节 → 64 位 hex）
     */
    public static function eddsa(): array
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            throw new \RuntimeException('EdDSA 需要 sodium 扩展，当前环境未安装');
        }

        $keypair = sodium_crypto_sign_keypair();

        return [
            'private' => sodium_bin2hex(sodium_crypto_sign_secretkey($keypair)),
            'public'  => sodium_bin2hex(sodium_crypto_sign_publickey($keypair)),
        ];
    }

    /**
     * 生成非对称密钥对（new / export / details 三步都带 config）
     *
     * @param array<string,mixed> $options openssl_pkey_new 参数
     * @param string              $label   错误信息前缀
     * @return array{private:string,public:string}
     */
    private static function asymmetric(array $options, string $label): array
    {
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException("{$label}: openssl 扩展不可用，无法生成密钥对");
        }

        $config = OpenSslConfig::withConfig($options);

        self::flushOpenSslErrors();

        $warning  = null;
        $resource = self::captureWarning(static fn () => openssl_pkey_new($config), $warning);
        if ($resource === false) {
            throw new \RuntimeException(
                "{$label}: 生成密钥对失败（openssl_pkey_new）：" . self::describeError($warning)
            );
        }

        self::flushOpenSslErrors();

        $privateKey = '';
        $warning = null;
        $exported = self::captureWarning(
            static function () use ($resource, $config, &$privateKey) {
                return openssl_pkey_export($resource, $privateKey, null, $config);
            },
            $warning
        );
        if ($exported === false || !is_string($privateKey) || $privateKey === '') {
            throw new \RuntimeException(
                "{$label}: 导出私钥失败（openssl_pkey_export）：" . self::describeError($warning)
            );
        }

        $details   = openssl_pkey_get_details($resource);
        $publicKey = is_array($details) && isset($details['key']) ? (string) $details['key'] : '';
        if ($publicKey === '') {
            throw new \RuntimeException(
                "{$label}: 导出公钥失败（openssl_pkey_get_details）：" . self::describeError(null)
            );
        }

        return ['private' => $privateKey, 'public' => $publicKey];
    }

    /**
     * 执行 openssl 调用并捕获其 PHP 告警（不向外冒泡）
     *
     * @param callable $fn 待执行的调用
     * @param string|null $warning 出参：捕获到的告警文本
     * @return mixed $fn 的返回值
     */
    private static function captureWarning(callable $fn, ?string &$warning): mixed
    {
        $warning = null;
        set_error_handler(static function (int $errno, string $message) use (&$warning): bool {
            $warning = $message;

            return true;
        });

        try {
            return $fn();
        } finally {
            restore_error_handler();
        }
    }

    /**
     * 组装可读的错误描述：优先 OpenSSL 错误队列，其次 PHP 告警
     */
    private static function describeError(?string $warning): string
    {
        $error = self::lastOpenSslError();
        if ($error !== '') {
            return $error;
        }

        return $warning !== null && $warning !== '' ? $warning : 'unknown openssl error';
    }

    /**
     * 清空 OpenSSL 错误队列，避免取到上一次调用的残留错误
     */
    private static function flushOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }

    /**
     * 取当前 OpenSSL 错误队列的首条信息（无错误时返回空串）
     */
    private static function lastOpenSslError(): string
    {
        $error = openssl_error_string();

        return $error !== false ? $error : '';
    }
}
