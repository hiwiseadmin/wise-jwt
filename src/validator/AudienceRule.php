<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 接收者校验规则
 */
class AudienceRule implements RuleInterface
{
    public function __construct(private string $expectedAudience) {}

    public function validate(array $payload): void
    {
        $aud = $payload['aud'] ?? null;
        if ($aud === null) {
            return;
        }
        // 支持单个或数组
        $audList = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->expectedAudience, $audList, true)) {
            throw new JwtException('接收者验证失败');
        }
    }
}
