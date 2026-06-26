<?php
declare(strict_types=1);

namespace wise\jwt\signer;

/**
 * 签名策略接口
 */
interface SignerInterface
{
    /**
     * 对 headerB64.payloadB64 签名
     */
    public function sign(string $headerB64, string $payloadB64): string;

    /**
     * 验证签名
     */
    public function verify(string $headerB64, string $payloadB64, string $signatureB64): bool;

    /**
     * 返回算法名称
     */
    public function algorithm(): string;

    /**
     * 返回 Key ID（JWK 场景使用）
     */
    public function kid(): ?string;
}
