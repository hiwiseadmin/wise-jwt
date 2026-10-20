<?php
declare(strict_types=1);

namespace wise\jwt\signer;

use wise\jwt\exception\SignatureInvalidException;

/**
 * ES512 签名器 — ECDSA P-521 + SHA512
 */
class ES512Signer extends AbstractSigner
{
    use EcdsaDerTrait;
    use ValidatesKeys;

    public const ALG = 'ES512';

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
            OPENSSL_ALGO_SHA512
        );
        if (!$success) {
            throw new SignatureInvalidException('ECDSA 签名失败');
        }
        // 第二参数为「单分量」字节数：P-521 = 66（总长 132，符合 RFC 7515）
        return $this->derToRaw($signature, 66);
    }

    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool
    {
        $key = openssl_pkey_get_public($this->publicKey);
        if ($key === false) {
            return false;
        }
        $derSignature = $this->rawToDer($signatureB64);
        $result = openssl_verify(
            $headerB64 . '.' . $payloadB64,
            $derSignature,
            $key,
            OPENSSL_ALGO_SHA512
        ) === 1;
        return $result;
    }

}
