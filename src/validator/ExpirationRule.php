<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 过期时间校验规则
 */
class ExpirationRule implements RuleInterface
{
    public function __construct(private int $leeway = 0) {}

    public function validate(array $payload): void
    {
        $exp = (int) ($payload['exp'] ?? 0);
        if ($exp > 0 && ($exp + $this->leeway) < time()) {
            throw new JwtException('令牌已过期');
        }
    }
}
