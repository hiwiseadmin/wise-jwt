<?php
declare(strict_types=1);

namespace wise\jwt\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Option;
use wise\jwt\JwtGuardManager;
use wise\jwt\blacklist\BlacklistInterface;
use wise\jwt\blacklist\DatabaseBlacklist;

/**
 * 管理 JWT 黑名单
 *
 * 用法：
 *   php think wise:jwt:blacklist:clear                # 清理过期黑名单记录
 *   php think wise:jwt:blacklist:clear --guard=admin  # 清理指定 guard
 *   php think wise:jwt:blacklist:stats                # 显示黑名单统计（子命令用 --stats）
 */
class BlacklistManage extends Command
{
    protected function configure(): void
    {
        $this->setName('wise:jwt:blacklist')
            ->addOption('guard', 'g', Option::VALUE_REQUIRED, '指定 Guard 名称')
            ->addOption('clear', 'c', Option::VALUE_NONE, '清理过期黑名单记录')
            ->addOption('stats', 's', Option::VALUE_NONE, '显示黑名单统计信息')
            ->addOption('flush', 'f', Option::VALUE_NONE, '清除所有黑名单记录（危险！）')
            ->setDescription('JWT 黑名单管理（清理过期记录、统计）')
            ->setHelp('管理 JWT 黑名单，支持清理过期记录和统计查询');
    }

    protected function execute(Input $input, Output $output): int
    {
        $guard = $input->getOption('guard');
        $clear = $input->getOption('clear');
        $stats = $input->getOption('stats');
        $flush = $input->getOption('flush');

        /** @var JwtGuardManager $manager */
        $manager = app(JwtGuardManager::class);
        $jwt = $manager->guard($guard);

        $blacklist = $jwt->getBlacklist();

        if ($blacklist === null) {
            $output->error('黑名单未启用');
            return 1;
        }

        if ($flush) {
            $output->warning('即将清除所有黑名单记录，此操作不可逆！');

            // Cache 驱动无法枚举 key，purge() 恒为 0：必须显式报错，
            // 否则运维会误以为黑名单已清空而实际并未生效。
            $flushable = $blacklist instanceof DatabaseBlacklist
                || $blacklist instanceof \wise\jwt\blacklist\RedisBlacklist;
            if (!$flushable) {
                $output->error('当前黑名单驱动不支持 flush（仅 redis / database 驱动支持）');
                return 1;
            }

            $count = $blacklist->purge();
            $output->success("已清空 {$count} 条黑名单记录");
            return 0;
        }

        if ($clear) {
            $count = $blacklist->purge();
            $output->success("已清理 {$count} 条过期黑名单记录");
            return 0;
        }

        if ($stats) {
            $this->showStats($output, $blacklist);
            return 0;
        }

        // 默认：帮助信息
        $output->info('JWT 黑名单管理');
        $output->writeln('  --clear        清理过期记录');
        $output->writeln('  --stats        显示统计信息');
        $output->writeln('  --guard=<name> 指定 Guard（默认 app）');

        return 0;
    }

    protected function showStats(Output $output, BlacklistInterface $blacklist): void
    {
        $guard = 'default';

        $output->info("黑名单统计 — Guard: {$guard}");

        // 尝试获取计数
        $type = get_class($blacklist);
        $output->writeln("  驱动类型: {$type}");

        // DatabaseBlacklist has table info
        if ($blacklist instanceof DatabaseBlacklist) {
            $output->writeln('  存储方式: 数据库（持久化）');
        } else {
            $output->writeln('  存储方式: 缓存（易失）');
        }
    }
}
