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
        $ttl = max(60, $expiresAt - time());
        return Cache::set($this->key($jti), 1, $ttl);
    }

    /** @var bool 非原子后端告警是否已发出（进程内一次） */
    private static bool $nonAtomicWarned = false;

    public function reserve(string $jti, int $expiresAt): bool
    {
        $ttl = max(60, $expiresAt - time());

        if (!self::$nonAtomicWarned && !$this->supportsAtomicAdd()) {
            self::$nonAtomicWarned = true;

            \wise\support\context\ContextualLogger::warning(
                '[JWT] 黑名单后端不支持原子 SETNX，Refresh Token 旋转在并发下可能被双花；'
                . '请将 wise-jwt.blacklist.driver 设为 redis'
            );
        }

        return Cache::add($this->key($jti), 1, $ttl);
    }

    /**
     * 当前缓存后端是否支持原子 ADD（SETNX）
     *
     * 仅 Redis（以及数据库唯一键）能保证；file 等驱动为 has + set 两步。
     */
    protected function supportsAtomicAdd(): bool
    {
        try {
            return Cache::store()->handler() instanceof \Redis;
        } catch (\Throwable) {
            return false;
        }
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
        return 0;
    }
}
