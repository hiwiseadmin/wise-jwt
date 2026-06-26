<?php
declare(strict_types=1);

namespace wise\jwt\exception;

/**
 * JWT 相关异常
 */
class JwtException extends \RuntimeException
{
    /**
     * @param string $message 异常消息
     * @param int $code 异常代码
     * @param \Throwable|null $previous 上一个异常
     */
    public function __construct(string $message = 'JWT 异常', int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
