<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

use think\facade\Db;

/**
 * 数据库黑名单驱动 — 持久化黑名单
 *
 * 依赖表结构：
 * CREATE TABLE jwt_blacklist (
 *   id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *   jti        VARCHAR(64)  NOT NULL UNIQUE,
 *   expires_at INT UNSIGNED NOT NULL,
 *   create_time INT UNSIGNED NOT NULL,
 *   INDEX idx_expires_at (expires_at)
 * );
 */
class DatabaseBlacklist extends AbstractBlacklist
{
    protected string $table;

    public function __construct(string $prefix = 'jwt:blacklist:', string $table = 'jwt_blacklist')
    {
        parent::__construct($prefix);
        $this->table = $table;
    }

    /**
     * @param string $table 自定义表名
     */
    public function setTable(string $table): self
    {
        $this->table = $table;
        return $this;
    }

    public function add(string $jti, int $expiresAt): bool
    {
        try {
            Db::table($this->table)->insert([
                'jti'        => $jti,
                'expires_at' => $expiresAt,
                'create_time' => time(),
            ]);
            return true;
        } catch (\Throwable) {
            // UNIQUE 约束冲突：jti 已存在，尝试更新过期时间
            try {
                Db::table($this->table)
                    ->where('jti', $jti)
                    ->update([
                        'expires_at' => $expiresAt,
                        'create_time' => time(),
                    ]);
                return true;
            } catch (\Throwable) {
                return false;
            }
        }
    }

    public function has(string $jti): bool
    {
        // 先惰性清理过期条目
        $this->cleanExpired();

        $row = Db::table($this->table)
            ->where('jti', $jti)
            ->find();

        return $row !== null;
    }

    public function remove(string $jti): bool
    {
        $affected = Db::table($this->table)
            ->where('jti', $jti)
            ->delete();

        return $affected > 0;
    }

    public function purge(): int
    {
        return Db::table($this->table)
            ->where('expires_at', '<', time())
            ->delete();
    }

    /**
     * 惰性清理过期条目（has() 时调用）
     */
    protected function cleanExpired(): void
    {
        // 使用概率性清理，避免每次 has() 都执行 DELETE 查询
        if (mt_rand(0, 99) < 5) {
            Db::table($this->table)
                ->where('expires_at', '<', time())
                ->delete();
        }
    }
}
