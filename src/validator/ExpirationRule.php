<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\TokenExpiredException;

/**
 * 过期时间校验规则
 */
class ExpirationRule implements RuleInterface
{
    public function __construct(private int $leeway = 0) {}

    public function validate(array $payload): void
    {
        // 缺少 exp 视为不合规令牌并拒绝（fail-closed），
        // 否则"检查过期"会在无 exp 的令牌上完全失效。
        $exp = (int) ($payload['exp'] ?? 0);
        if ($exp <= 0 || ($exp + $this->leeway) < time()) {
            throw new TokenExpiredException('令牌已过期');
        }
    }
}
