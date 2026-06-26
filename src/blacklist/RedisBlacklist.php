<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

use think\facade\Cache;

/**
 * Redis 黑名单 — 基于 Redis Sorted Set，支持 purge 清理过期条目
 */
class RedisBlacklist extends AbstractBlacklist
{
    protected function redis()
    {
        return Cache::store('redis')->handler();
    }

    public function add(string $jti, int $expiresAt): bool
    {
        return (bool) $this->redis()->zAdd($this->prefix . 'set', $expiresAt, $jti);
    }

    public function has(string $jti): bool
    {
        // 概率性清理过期条目（5% 概率），避免每次 has() 都执行 O(log N) 清理
        if (mt_rand(0, 99) < 5) {
            $this->redis()->zRemRangeByScore($this->prefix . 'set', 0, time());
        }
        return (bool) $this->redis()->zScore($this->prefix . 'set', $jti);
    }

    public function remove(string $jti): bool
    {
        return (bool) $this->redis()->zRem($this->prefix . 'set', $jti);
    }

    public function purge(): int
    {
        return $this->redis()->zRemRangeByScore($this->prefix . 'set', 0, time());
    }
}
