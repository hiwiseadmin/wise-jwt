<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

use think\facade\Cache;

/**
 * Redis 黑名单 — 基于 Redis Sorted Set，支持 purge 清理过期条目
 */
class RedisBlacklist extends AbstractBlacklist
{
    /** 惰性清理触发概率（百分比，0-100） */
    protected int $cleanupProbability = 5;

    public function __construct(string $prefix = 'jwt:blacklist:', int $cleanupProbability = 5)
    {
        parent::__construct($prefix);
        $this->setCleanupProbability($cleanupProbability);
    }

    /**
     * 设置惰性清理概率（0=禁用概率性清理，100=每次都清理）
     */
    public function setCleanupProbability(int $probability): self
    {
        $this->cleanupProbability = max(0, min(100, $probability));
        return $this;
    }

    protected function redis()
    {
        return Cache::store('redis')->handler();
    }

    public function add(string $jti, int $expiresAt): bool
    {
        return (bool) $this->redis()->zAdd($this->prefix . 'set', $expiresAt, $jti);
    }

    public function reserve(string $jti, int $expiresAt): bool
    {
        return (bool) $this->redis()->zAdd($this->prefix . 'set', ['nx'], $expiresAt, $jti);
    }

    public function has(string $jti): bool
    {
        if ($this->cleanupProbability > 0 && mt_rand(0, 99) < $this->cleanupProbability) {
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
