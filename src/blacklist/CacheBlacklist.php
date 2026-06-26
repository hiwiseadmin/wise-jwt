<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

use think\facade\Cache;

/**
 * 缓存黑名单 — 基于 ThinkPHP Cache
 */
class CacheBlacklist extends AbstractBlacklist
{
    public function add(string $jti, int $expiresAt): bool
    {
        $ttl = max(0, $expiresAt - time());
        return Cache::set($this->key($jti), 1, $ttl);
    }

    public function has(string $jti): bool
    {
        return Cache::has($this->key($jti));
    }

    public function remove(string $jti): bool
    {
        return Cache::delete($this->key($jti));
    }

    public function purge(): int
    {
        // Cache 驱动不支持批量查询，返回 0
        return 0;
    }
}
