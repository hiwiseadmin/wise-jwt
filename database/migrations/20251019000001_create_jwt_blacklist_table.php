<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * JWT 黑名单表 — 数据库驱动黑名单持久化
 *
 * 使用：
 * 1. 运行迁移：php think migrate:run
 * 2. 配置 blacklist.driver = 'database'
 *
 * 字段类型约定：
 * - expires_at：无符号 INT，存 Unix 秒级时间戳（与 JWT 的 exp 声明同源），
 *   参与 `WHERE expires_at < time()` 的绝对时刻比较，必须保持整型以免引入时区耦合；
 *   无符号可避免 2038 溢出（上限延至 2106-02-07）。
 * - create_time：datetime，与框架 create_time 约定一致（仅留痕，不参与任何比较）。
 */
class CreateJwtBlacklistTable extends Migrator
{
    public function up(): void
    {
        $table = $this->table('jwt_blacklist', [
            'engine' => 'InnoDB',
            'comment' => 'JWT 令牌黑名单',
        ]);

        $table->addColumn(Column::string('jti', 64)->setNull(false)->setComment('JWT ID'))
            ->addColumn(Column::integer('expires_at')->setUnsigned()->setNull(false)->setComment('过期时间戳（Unix 秒）'))
            ->addColumn(Column::datetime('create_time')->setNull(false)->setComment('创建时间'))
            ->addIndex(['jti'], ['unique' => true, 'name' => 'idx_jti'])
            ->addIndex(['expires_at'], ['name' => 'idx_expires_at'])
            ->create();
    }

    public function down(): void
    {
        if ($this->hasTable('jwt_blacklist')) {
            $this->table('jwt_blacklist')->drop()->save();
        }
    }
}
