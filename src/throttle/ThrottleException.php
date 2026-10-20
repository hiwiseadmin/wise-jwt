<?php
declare(strict_types=1);

namespace wise\jwt\throttle;

use wise\jwt\exception\ErrorCode;
use wise\jwt\exception\JwtException;

/**
 * 频率限制异常 — 请求过于频繁
 *
 * 错误码：ErrorCode::THROTTLED (50100)
 * HTTP：429
 */
class ThrottleException extends JwtException
{
    protected int $retryAfter;

    /**
     * @param string           $message    异常消息
     * @param int              $code       业务错误码
     * @param int              $retryAfter 重试等待秒数
     * @param \Throwable|null  $previous   上一个异常
     */
    public function __construct(
        string $message = '请求过于频繁，请稍后再试',
        int $code = ErrorCode::THROTTLED->value,
        int $retryAfter = 60,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous, 429);
        $this->retryAfter = $retryAfter;
    }

    /**
     * 获取重试等待秒数
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
