<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 签发时间校验规则
 */
class IssuedAtRule implements RuleInterface
{
    public function __construct(private int $leeway = 0) {}

    public function validate(array $payload): void
    {
        $iat = (int) ($payload['iat'] ?? 0);
        if ($iat > 0 && ($iat - $this->leeway) > time()) {
            throw new JwtException('令牌签发时间异常');
        }
    }
}
