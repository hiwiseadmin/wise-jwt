<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

/**
 * 黑名单存储接口
 */
interface BlacklistInterface
{
    /** 将 jti 加入黑名单，过期时间戳 */
    public function add(string $jti, int $expiresAt): bool;

    /** 检查 jti 是否在黑名单中 */
    public function has(string $jti): bool;

    /** 移除 jti */
    public function remove(string $jti): bool;

    /** 清理过期条目 */
    public function purge(): int;
}
