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

    /**
     * 原子占位：仅当 jti 尚不存在时写入并返回 true，已存在返回 false。
     *
     * 用于 Refresh Token Rotation 等「检查-写入」必须原子的场景
     * （等价于 Redis ZADD NX / Cache add）。自定义驱动需同步实现。
     */
    public function reserve(string $jti, int $expiresAt): bool;

    /** 检查 jti 是否在黑名单中 */
    public function has(string $jti): bool;

    /** 移除 jti */
    public function remove(string $jti): bool;

    /** 清理过期条目 */
    public function purge(): int;
}
