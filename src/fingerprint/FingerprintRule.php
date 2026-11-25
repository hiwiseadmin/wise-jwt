<?php
declare(strict_types=1);

namespace wise\jwt\fingerprint;

use wise\jwt\validator\RuleInterface;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\TokenInvalidException;

/**
 * 指纹校验规则 — 解析时验证设备/IP 指纹
 */
class FingerprintRule implements RuleInterface
{
    protected TokenFingerprinter $fingerprinter;
    protected bool $strict;

    /**
     * @param TokenFingerprinter $fingerprinter  指纹生成器
     * @param bool               $strict         严格模式（不匹配则拒绝）
     */
    public function __construct(TokenFingerprinter $fingerprinter, bool $strict = true)
    {
        $this->fingerprinter = $fingerprinter;
        $this->strict = $strict;
    }

    public function validate(array $payload): void
    {
        if (!isset($payload['fph'])) {
            if ($this->strict) {
                throw new TokenInvalidException('令牌缺少设备指纹');
            }
            return;
        }

        if (!$this->fingerprinter->verify($payload['fph'])) {
            throw new TokenInvalidException('设备指纹不匹配，可能在其他设备上使用');
        }
    }
}
