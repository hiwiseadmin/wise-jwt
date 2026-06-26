<?php
declare(strict_types=1);

namespace wise\jwt\throttle;

use wise\jwt\exception\JwtException;

/**
 * 频率限制异常 — 请求过于频繁
 */
class ThrottleException extends JwtException
{
    protected int $retryAfter;

    public function __construct(string $message = '请求过于频繁，请稍后再试', int $code = 429, int $retryAfter = 60, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->retryAfter = $retryAfter;
    }

    /** 获取重试等待秒数 */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
