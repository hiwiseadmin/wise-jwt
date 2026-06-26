<?php
declare(strict_types=1);

namespace wise\jwt\throttle;

use think\facade\Cache;

/**
 * JWT 频率限制器 — 滑动窗口算法
 *
 * 用法：
 * $limiter = new RateLimiter(5, 60); // 每分钟最多 5 次
 * $limiter->hit('ip:192.168.1.1');   // 返回剩余次数，0 表示超限
 */
class RateLimiter
{
    protected int $maxAttempts;
    protected int $decaySeconds;

    /** @var string 缓存前缀 */
    protected string $prefix;

    public function __construct(int $maxAttempts = 5, int $decaySeconds = 60, string $prefix = 'jwt:throttle:')
    {
        $this->maxAttempts = $maxAttempts;
        $this->decaySeconds = $decaySeconds;
        $this->prefix = $prefix;
    }

    /**
     * 记录一次尝试，返回剩余次数
     *
     * @param string $key 标识符（如 ip:192.168.1.1）
     * @return int 剩余次数（0 表示已达上限，不允许再试）
     */
    public function hit(string $key): int
    {
        $cacheKey = $this->prefix . $key;
        $attempts = (int) Cache::get($cacheKey, 0);

        if ($attempts >= $this->maxAttempts) {
            return 0;
        }

        $attempts++;

        // 每次递增都刷新 TTL，保证窗口准确
        Cache::set($cacheKey, $attempts, $this->decaySeconds);

        return $this->maxAttempts - $attempts;
    }

    /**
     * 检查是否超限
     */
    public function tooManyAttempts(string $key): bool
    {
        $cacheKey = $this->prefix . $key;
        $attempts = (int) Cache::get($cacheKey, 0);
        return $attempts >= $this->maxAttempts;
    }

    /**
     * 获取剩余尝试次数
     */
    public function remaining(string $key): int
    {
        $cacheKey = $this->prefix . $key;
        $attempts = (int) Cache::get($cacheKey, 0);
        return max(0, $this->maxAttempts - $attempts);
    }

    /**
     * 获取冷却剩余秒数
     *
     * 仅在已超限时才有意义，未超限返回 0
     */
    public function cooldown(string $key): int
    {
        $cacheKey = $this->prefix . $key;
        $attempts = Cache::get($cacheKey);

        if ($attempts === null || $attempts === false) {
            return 0;
        }

        // 未超限则无需冷却
        if ((int) $attempts < $this->maxAttempts) {
            return 0;
        }

        // 使用 driver handle 获取 TTL（如果可用）
        try {
            $handle = Cache::store()->handler();
            if ($handle instanceof \Redis) {
                $ttl = $handle->ttl($cacheKey);
                return $ttl > 0 ? $ttl : 0;
            }
        } catch (\Throwable) {
            // 驱动不支持 TTL 查询
        }

        // 非 Redis 驱动：返回完整的衰减时间作为保守估计
        // 注意：可能偏高，但至少不会低估（安全性优先）
        return $this->decaySeconds;
    }

    /**
     * 重置计数
     */
    public function clear(string $key): void
    {
        Cache::delete($this->prefix . $key);
    }

    /**
     * 获取限流配置
     */
    public function getConfig(): array
    {
        return [
            'max_attempts'  => $this->maxAttempts,
            'decay_seconds' => $this->decaySeconds,
        ];
    }
}
