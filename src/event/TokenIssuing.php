<?php
declare(strict_types=1);

namespace wise\jwt\event;

/**
 * 令牌签发前事件（可修改 payload）
 */
class TokenIssuing
{
    public function __construct(public array &$payload) {}
}
