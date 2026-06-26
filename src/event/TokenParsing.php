<?php
declare(strict_types=1);

namespace wise\jwt\event;

/**
 * 令牌解析前事件
 */
class TokenParsing
{
    public function __construct(public string $token) {}
}
