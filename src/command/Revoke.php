<?php
declare(strict_types=1);

namespace wise\jwt\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Argument;
use think\console\input\Option;

/**
 * 按 jti 吊销指定 token
 *
 * 用法：
 *   php think wise:jwt:revoke <jti>                    # 按 jti 吊销
 *   php think wise:jwt:revoke <token> --by-token       # 按 token 字符串吊销
 */
class Revoke extends Command
{
    protected function configure(): void
    {
        $this->setName('wise:jwt:revoke')
            ->addArgument('target', Argument::REQUIRED, 'jti 或 token 字符串')
            ->addOption('by-token', 'T', Option::VALUE_NONE, '按 token 字符串吊销（默认按 jti）')
            ->addOption('guard', 'g', Option::VALUE_REQUIRED, '指定 Guard 名称')
            ->setDescription('吊销指定的 JWT 令牌')
            ->setHelp('按 jti 或完整 token 吊销 JWT 令牌');
    }

    protected function execute(Input $input, Output $output): int
    {
        $target = $input->getArgument('target');
        $byToken = $input->getOption('by-token');
        $guard = $input->getOption('guard');

        /** @var \wise\jwt\JwtGuardManager $manager */
        $manager = app(\wise\jwt\JwtGuardManager::class);
        $jwt = $manager->guard($guard);

        if ($byToken) {
            // 按完整 token 吊销
            $payload = $jwt->decode($target);
            if ($payload === null) {
                $output->error('令牌格式无效');
                return 1;
            }

            $jti = $payload['jti'] ?? '';
            $sub = $payload['sub'] ?? 'unknown';
            $exp = isset($payload['exp']) ? date('Y-m-d H:i:s', (int) $payload['exp']) : 'unknown';

            $output->info("令牌信息: jti={$jti}, sub={$sub}, exp={$exp}");

            if ($jwt->revoke($target)) {
                $output->success("令牌已吊销: {$jti}");
                return 0;
            } else {
                $output->error("吊销失败，可能已被吊销或令牌无效");
                return 1;
            }
        }

        // 按 jti 吊销
        $jti = $target;
        if ($jwt->isRevoked($jti)) {
            $output->warning("该 jti 已在黑名单中: {$jti}");
            return 0;
        }

        if ($jwt->revokeByJti($jti)) {
            $output->success("jti 已加入黑名单: {$jti}");
            return 0;
        }

        $output->error("吊销失败: {$jti}");
        return 1;
    }
}
