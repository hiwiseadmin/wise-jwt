<?php
declare(strict_types=1);

namespace wise\jwt\blacklist;

use think\facade\Db;
use wise\support\context\ContextualLogger;
use Exception;

/**
 * 数据库黑名单驱动 — 持久化黑名单
 *
 * 依赖表结构（逻辑表名 `jwt_blacklist`，物理表名 = `database.prefix` + 逻辑名，当前为 `ws_jwt_blacklist`；
 * 本类统一用 `Db::name()` 访问，前缀由连接配置决定）：
 * CREATE TABLE jwt_blacklist (
 *   id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *   jti         VARCHAR(64)  NOT NULL UNIQUE,
 *   expires_at  INT UNSIGNED NOT NULL COMMENT '过期时间戳（Unix 秒）',
 *   create_time DATETIME     NOT NULL COMMENT '创建时间',
 *   INDEX idx_expires_at (expires_at)
 * );
 *
 * 类型说明：
 * - expires_at 保持整型秒级时间戳（无符号 INT），与 JWT 的 exp 声明同源，
 *   全程与 time() 直接比较，不做日期字符串转换，避免引入时区耦合；
 * - create_time 为 datetime，与框架时间字段约定一致，写入时格式化为 'Y-m-d H:i:s'。
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
            Db::name($this->table)->insert([
                'jti'        => $jti,
                'expires_at' => $expiresAt,
                'create_time' => date('Y-m-d H:i:s'),
            ]);
            return true;
        } catch (\think\db\exception\PDOException $e) {
            // ThinkPHP 会把底层 \PDOException 包装为 think\db\exception\PDOException，
            // 其 getCode() 恒为 10501，真正的 SQLSTATE 需从 getData() 读取。
            $pdoInfo = $e->getData()['PDO Error Info'] ?? [];
            if (($pdoInfo['SQLSTATE'] ?? '') === '23000') {
                try {
                    Db::name($this->table)
                        ->where('jti', $jti)
                        ->update([
                            'expires_at' => $expiresAt,
                            'create_time' => date('Y-m-d H:i:s'),
                        ]);
                    return true;
                } catch (Exception $updateEx) {
                    ContextualLogger::warning('[JWT] DatabaseBlacklist update failed', [
                        'jti' => $jti, 'error' => $updateEx->getMessage(),
                    ]);
                    return false;
                }
            }

            ContextualLogger::error('[JWT] DatabaseBlacklist insert failed', [
                'jti' => $jti, 'error' => $e->getMessage(),
            ]);
            return false;
        } catch (Exception $e) {
            ContextualLogger::error('[JWT] DatabaseBlacklist unexpected error', [
                'jti' => $jti, 'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    public function reserve(string $jti, int $expiresAt): bool
    {
        // 依赖 jti 唯一索引：插入成功即占位成功；重复插入抛异常则返回 false（不更新时间）。
        try {
            Db::name($this->table)->insert([
                'jti'         => $jti,
                'expires_at'  => $expiresAt,
                'create_time' => date('Y-m-d H:i:s'),
            ]);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    public function has(string $jti): bool
    {
        // 先惰性清理过期条目
        $this->cleanExpired();

        $row = Db::name($this->table)
            ->where('jti', $jti)
            ->find();

        return $row !== null;
    }

    public function remove(string $jti): bool
    {
        $affected = Db::name($this->table)
            ->where('jti', $jti)
            ->delete();

        return $affected > 0;
    }

    public function purge(): int
    {
        return Db::name($this->table)
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
            Db::name($this->table)
                ->where('expires_at', '<', time())
                ->delete();
        }
    }
}
