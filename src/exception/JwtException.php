<?php
declare(strict_types=1);

namespace wise\jwt\exception;

use wise\support\exception\WiseException;

/**
 * JWT 相关异常
 *
 * 所有 JWT 异常的基类，捕获此异常等同于捕获所有 JWT 异常。
 *
 * 错误码：ErrorCode::JWT_ERROR (50000)
 * HTTP：400
 */
class JwtException extends WiseException
{
    /**
     * @param string           $message  异常消息
     * @param int              $code     业务错误码（默认 ErrorCode::JWT_ERROR）
     * @param \Throwable|null  $previous 上一个异常
     * @param int              $httpCode HTTP 状态码（默认 400）
     */
    public function __construct(
        string $message = 'JWT 异常',
        int $code = ErrorCode::JWT_ERROR->value,
        ?\Throwable $previous = null,
        int $httpCode = 400,
    ) {
        parent::__construct($code, $message, $httpCode, $previous);
    }
}
