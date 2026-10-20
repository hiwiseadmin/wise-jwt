<?php
declare(strict_types=1);

namespace wise\jwt\event;

/**
 * 令牌解析后事件
 */
class TokenParsed
{
    public function __construct(
        public string $token,
        public array $payload
    ) {}
}
