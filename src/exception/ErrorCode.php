<?php
declare(strict_types=1);

namespace wise\jwt\exception;

use wise\support\exception\ErrorCodeInterface;

/**
 * wise-jwt 业务错误码（号段 50000~59999）
 *
 * 号段分配约定（见 wise-support\exception\WiseException 号段全景）：
 *  50000~50099  令牌校验（过期/无效/吊销/签名）
 *  50100~50199  频率限制
 *
 * 每个错误码均通过 defaultMessage() 提供默认中文说明，
 * 抛异常时使用 WiseException::of() 自动携带，无需重复手写。
 *
 * @package wise\jwt\exception
 */
enum ErrorCode: int implements ErrorCodeInterface
{
    /** 通用 JWT 异常 */
    case JWT_ERROR         = 50000;

    /** 令牌已过期 */
    case TOKEN_EXPIRED     = 50001;

    /** 令牌无效 */
    case TOKEN_INVALID     = 50002;

    /** 令牌已被吊销（黑名单） */
    case TOKEN_BLACKLISTED = 50003;

    /** 签名验证失败 */
    case SIGNATURE_INVALID = 50004;

    /** 请求未携带认证令牌 */
    case TOKEN_MISSING     = 50005;

    /** 请求过于频繁（限流） */
    case THROTTLED         = 50100;

    /**
     * 错误码对应的默认中文说明
     */
    public function defaultMessage(): string
    {
        return match ($this) {
            self::JWT_ERROR         => 'JWT 异常',
            self::TOKEN_EXPIRED     => '令牌已过期',
            self::TOKEN_INVALID     => '令牌无效',
            self::TOKEN_BLACKLISTED => '令牌已被吊销',
            self::SIGNATURE_INVALID => '签名验证失败',
            self::TOKEN_MISSING     => '缺少认证令牌',
            self::THROTTLED         => '请求过于频繁，请稍后再试',
        };
    }
}
