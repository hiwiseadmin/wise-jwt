<?php
declare(strict_types=1);

namespace wise\jwt\signer;

/**
 * 签名器抽象基类 — 提供 base64url 编解码公共方法
 */
abstract class AbstractSigner implements SignerInterface
{
    /**
     * Key ID
     */
    protected ?string $kid = null;

    /**
     * 算法名称（子类常量 ALG）
     */
    abstract public function algorithm(): string;

    /**
     * Key ID（默认 null，可通过 setKid() 设置）
     */
    public function kid(): ?string
    {
        return $this->kid;
    }

    /**
     * 设置 Key ID（密钥轮换用）
     */
    public function setKid(string $kid): self
    {
        $this->kid = $kid;
        return $this;
    }

    /**
     * Base64 URL 安全编码
     */
    protected function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    /**
     * Base64 URL 安全解码
     */
    protected function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(str_replace(['-', '_'], ['+', '/'], $data), true);
        return $decoded !== false ? $decoded : '';
    }
}
