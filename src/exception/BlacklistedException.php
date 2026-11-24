<?php
declare(strict_types=1);

namespace wise\jwt\exception;

/**
 * 令牌已被吊销异常
 *
 * 错误码：ErrorCode::TOKEN_BLACKLISTED (50003)
 * HTTP：401
 */
class BlacklistedException extends JwtException
{
    /**
     * @param string           $message  异常消息
     * @param int              $code     业务错误码
     * @param \Throwable|null  $previous 上一个异常
     */
    public function __construct(
        string $message = '令牌已被吊销',
        int $code = ErrorCode::TOKEN_BLACKLISTED->value,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous, 401);
    }
}
