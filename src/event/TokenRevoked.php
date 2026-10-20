<?php
declare(strict_types=1);

namespace wise\jwt\event;

/**
 * 令牌吊销后事件
 */
class TokenRevoked
{
    public function __construct(public string $jti) {}
}
