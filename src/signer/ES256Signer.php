<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\SignatureInvalidException;

/**
 * ES256 签名器 — ECDSA P-256 + SHA256
 */
class ES256Signer extends AbstractSigner
{
    use EcdsaDerTrait;
    use ValidatesKeys;

    public const ALG = 'ES256';

    public function __construct(
        protected string $privateKey,
        protected string $publicKey
    ) {
        $this->validateKeys($this->privateKey, $this->publicKey, self::ALG);
    }

    public function algorithm(): string { return self::ALG; }

    public function sign(string $headerB64, string $payloadB64): string
    {
        $key = openssl_pkey_get_private($this->privateKey);
        if ($key === false) {
            throw new SignatureInvalidException('无效的 ECDSA 私钥');
        }
        $success = openssl_sign(
            $headerB64 . '.' . $payloadB64,
            $signature,
            $key,
            OPENSSL_ALGO_SHA256
        );
        openssl_free_key($key);
        if (!$success) {
            throw new SignatureInvalidException('ECDSA 签名失败');
        }
        // ECDSA 签名的 DER 格式需要转换为 raw 格式（r||s）
        return $this->derToRaw($signature, 64);
    }

    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool
    {
        $key = openssl_pkey_get_public($this->publicKey);
        if ($key === false) {
            return false;
        }
        // 将 raw 格式转换回 DER
        $derSignature = $this->rawToDer($signatureB64);
        $result = openssl_verify(
            $headerB64 . '.' . $payloadB64,
            $derSignature,
            $key,
            OPENSSL_ALGO_SHA256
        ) === 1;
        openssl_free_key($key);
        return $result;
    }

}
