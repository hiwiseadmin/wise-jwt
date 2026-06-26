<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

/**
 * 黑名单抽象基类
 */
abstract class AbstractBlacklist implements BlacklistInterface
{
    protected string $prefix;

    public function __construct(string $prefix = 'jwt:blacklist:')
    {
        $this->prefix = $prefix;
    }

    protected function key(string $jti): string
    {
        return $this->prefix . $jti;
    }
}
