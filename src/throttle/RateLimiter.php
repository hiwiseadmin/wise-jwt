<?php

declare(strict_types=1);

namespace wise\jwt\throttle;

use wise\support\rate\RateLimiter as SupportRateLimiter;

/**
 * JWT 频率限制器 — 兼容适配器
 *
 * 实际限流逻辑已委托至 {@see \wise\support\rate\RateLimiter}。
 * 本类保留旧版 API（key 作为方法参数）以保持向后兼容。
 *
 * 用法：
 * $limiter = new RateLimiter(5, 60, 'jwt:throttle:');
 * $limiter->tooManyAttempts('ip:192.168.1.1');
 * $limiter->hit('ip:192.168.1.1');
 *
 * @package wise\jwt\throttle
 */
class RateLimiter
{
    private int $maxAttempts;
    private int $decaySeconds;
    private string $prefix;

    public function __construct(int $maxAttempts = 5, int $decaySeconds = 60, string $prefix = 'jwt:throttle:')
    {
        $this->maxAttempts  = $maxAttempts;
        $this->decaySeconds = $decaySeconds;
        $this->prefix       = $prefix;
    }

    /**
     * 记录一次尝试，返回剩余次数
     */
    public function hit(string $key): int
    {
        return $this->limiter($key)->hit();
    }

    /**
     * 检查是否超限
     */
    public function tooManyAttempts(string $key): bool
    {
        return $this->limiter($key)->tooManyAttempts();
    }

    /**
     * 获取剩余尝试次数
     */
    public function remaining(string $key): int
    {
        return $this->limiter($key)->remaining();
    }

    /**
     * 获取冷却剩余秒数（仅在已超限时有效）
     */
    public function cooldown(string $key): int
    {
        return $this->limiter($key)->cooldown();
    }

    /**
     * 重置计数
     */
    public function clear(string $key): void
    {
        $this->limiter($key)->clear();
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

    /**
     * 构建底层限流器实例
     */
    private function limiter(string $key): SupportRateLimiter
    {
        return SupportRateLimiter::for($this->maxAttempts, $this->decaySeconds)
            ->withPrefix($this->prefix)
            ->by($key);
    }
}
