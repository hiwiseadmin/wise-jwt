<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 生效时间校验规则
 */
class NotBeforeRule implements RuleInterface
{
    public function __construct(private int $leeway = 0) {}

    public function validate(array $payload): void
    {
        $nbf = (int) ($payload['nbf'] ?? 0);
        if ($nbf > 0 && ($nbf - $this->leeway) > time()) {
            throw new JwtException('令牌尚未生效');
        }
    }
}
