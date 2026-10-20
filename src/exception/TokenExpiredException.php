<?php
declare(strict_types=1);

namespace wise\jwt\exception;

/**
 * 令牌已过期异常
 *
 * 错误码：ErrorCode::TOKEN_EXPIRED (50001)
 * HTTP：401
 */
class TokenExpiredException extends JwtException
{
    /**
     * @param string           $message  异常消息
     * @param int              $code     业务错误码
     * @param \Throwable|null  $previous 上一个异常
     */
    public function __construct(
        string $message = '令牌已过期',
        int $code = ErrorCode::TOKEN_EXPIRED->value,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous, 401);
    }
}
