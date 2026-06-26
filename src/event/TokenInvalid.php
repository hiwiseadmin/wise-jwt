<?php
declare(strict_types=1);

namespace wise\jwt\event;

/**
 * 令牌校验失败事件
 */
class TokenInvalid
{
    public function __construct(
        public string $token,
        public string $reason
    ) {}
}
