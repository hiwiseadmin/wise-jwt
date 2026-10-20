<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\JwtException;

/**
 * EdDSA 签名器 — Ed25519 (需要 sodium 扩展，PHP 7.2+)
 *
 * 私钥格式支持：
 * - 64 字节 Ed25519 secret key（seed + public key），直接使用
 * - 32 字节 Ed25519 seed，自动转换为 64 字节 secret key
 * - base64 编码的上述任一格式
 */
class EdDSASigner extends AbstractSigner
{
    public const ALG = 'EdDSA';

    /** Ed25519 seed 长度（字节） */
    private const ED25519_SEED_BYTES = 32;
    /** Ed25519 secret key 长度（字节） */
    private const ED25519_SECRETKEY_BYTES = 64;

    public function __construct(
        protected string $privateKey,
        protected string $publicKey
    ) {
        if (!extension_loaded('sodium')) {
            throw new \RuntimeException('EdDSA 签名需要 sodium 扩展');
        }
        if ($this->privateKey === '') {
            throw new JwtException('EdDSA 私钥不能为空');
        }
        if ($this->publicKey === '') {
            throw new JwtException('EdDSA 公钥不能为空');
        }

        // 自动转换 32 字节 seed → 64 字节 secret key
        $this->privateKey = $this->normalizeSecretKey($this->privateKey);
    }

    public function algorithm(): string { return self::ALG; }

    public function sign(string $headerB64, string $payloadB64): string
    {
        return sodium_crypto_sign_detached(
            $headerB64 . '.' . $payloadB64,
            $this->privateKey
        );
    }

    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool
    {
        return sodium_crypto_sign_verify_detached(
            $signatureB64,
            $headerB64 . '.' . $payloadB64,
            $this->publicKey
        );
    }

    /**
     * 规范化 Ed25519 私钥：将 32 字节 seed 转换为 64 字节 secret key
     *
     * sodium_crypto_sign_detached() 需要 64 字节的 Ed25519 secret key，
     * 如果用户提供的是 32 字节 seed，则自动通过 sodium_crypto_sign_seed_keypair() 转换。
     * 支持 hex 编码和 base64 编码的 seed/secret key。
     */
    private function normalizeSecretKey(string $key): string
    {
        $raw = $key;

        // 检测 hex 编码（纯十六进制字符，长度是偶数）
        if ($this->looksLikeHex($key)) {
            $raw = hex2bin($key);
        } elseif (!ctype_print($key) || $this->looksLikeBase64($key)) {
            // 尝试 base64 解码（如果原始字符串包含 base64 特征）
            $decoded = base64_decode($key, true);
            if ($decoded !== false) {
                $raw = $decoded;
            }
        }

        $len = strlen($raw);

        // 已经是 64 字节的 secret key，直接返回
        if ($len === self::ED25519_SECRETKEY_BYTES) {
            return $raw;
        }

        // 32 字节 seed，转换为 64 字节 secret key
        if ($len === self::ED25519_SEED_BYTES) {
            $keypair = sodium_crypto_sign_seed_keypair($raw);
            return sodium_crypto_sign_secretkey($keypair);
        }

        // 长度不匹配，可能是 PEM 格式或其他编码，直接返回让 sodium 自行报错
        return $key;
    }

    /**
     * 判断字符串是否看起来像 hex 编码
     */
    private function looksLikeHex(string $str): bool
    {
        return strlen($str) % 2 === 0
            && preg_match('#^[0-9a-fA-F]+$#', $str) === 1
            && strlen($str) >= 64; // 至少 32 字节 hex（seed 最小长度）
    }

    /**
     * 判断字符串是否看起来像 base64 编码
     */
    private function looksLikeBase64(string $str): bool
    {
        return strlen($str) > 40
            && preg_match('#^[A-Za-z0-9+/]+=*$#', $str) === 1;
    }
}
