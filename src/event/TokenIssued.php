<?php
declare(strict_types=1);

namespace wise\jwt\event;

/**
 * 令牌签发后事件
 */
class TokenIssued
{
    public function __construct(
        public string $token,
        public array $payload
    ) {}
}
