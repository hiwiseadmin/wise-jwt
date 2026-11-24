<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\SignatureInvalidException;

/**
 * RS384 签名器 — RSA-SHA384
 */
class RS384Signer extends AbstractSigner
{
    use ValidatesKeys;

    public const ALG = 'RS384';

    public function __construct(
        protected string $privateKey,
        protected string $publicKey
    ) {
        $this->validateKeys($this->privateKey, $this->publicKey, self::ALG);
    }

    public function algorithm(): string { return self::ALG; }

    public function sign(string $headerB64, string $payloadB64): string
    {
        $success = openssl_sign(
            $headerB64 . '.' . $payloadB64,
            $signature,
            $this->privateKey,
            OPENSSL_ALGO_SHA384
        );
        if (!$success) {
            throw new SignatureInvalidException('OpenSSL 签名失败');
        }
        return $signature;
    }

    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool
    {
        return openssl_verify(
            $headerB64 . '.' . $payloadB64,
            $signatureB64,
            $this->publicKey,
            OPENSSL_ALGO_SHA384
        ) === 1;
    }
}
