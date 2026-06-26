<?php
declare(strict_types=1);

use think\migration\Migrator;

/**
 * JWT 黑名单表 — 数据库驱动黑名单持久化
 *
 * 使用：
 * 1. 发布迁移：php think wise:jwt:publish
 * 2. 运行迁移：php think migrate:run
 * 3. 配置 blacklist.driver = 'database'
 */
class CreateJwtBlacklistTable extends Migrator
{
    public function change(): void
    {
        $table = $this->table('jwt_blacklist', [
            'engine' => 'InnoDB',
            'comment' => 'JWT 令牌黑名单',
        ]);

        $table->addColumn('jti', 'string', ['limit' => 64, 'null' => false, 'comment' => 'JWT ID'])
            ->addColumn('expires_at', 'integer', ['null' => false, 'comment' => '过期时间戳'])
            ->addColumn('create_time', 'integer', ['null' => false, 'comment' => '创建时间戳'])
            ->addIndex(['jti'], ['unique' => true, 'name' => 'idx_jti'])
            ->addIndex(['expires_at'], ['name' => 'idx_expires_at'])
            ->create();
    }
}
