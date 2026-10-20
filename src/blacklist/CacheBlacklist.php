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
        // 最小 TTL 保护：如果已过期则设置 60s 缓冲，防止驱动对 TTL=0 行为不一致
        $ttl = max(60, $expiresAt - time());
        return Cache::set($this->key($jti), 1, $ttl);
    }

    public function reserve(string $jti, int $expiresAt): bool
    {
        // Cache::add 为 SETNX 语义：键已存在返回 false，保证「检查-写入」原子，
        // 用于 Refresh Token Rotation 防并发重放。
        $ttl = max(60, $expiresAt - time());
        return Cache::add($this->key($jti), 1, $ttl);
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
