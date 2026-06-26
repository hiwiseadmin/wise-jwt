<?php
declare(strict_types=1);

namespace wise\jwt\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Argument;
use wise\jwt\Jwt;

/**
 * 解码 JWT payload（不验签）
 *
 * 用法：
 *   php think wise:jwt:decode <token>              # 解码 payload
 *   php think wise:jwt:decode <token> --json       # JSON 格式化输出
 *   php think wise:jwt:decode <token> --details    # 显示详细信息（过期时间、剩余时间）
 */
class Decode extends Command
{
    protected function configure(): void
    {
        $this->setName('wise:jwt:decode')
            ->addArgument('token', Argument::REQUIRED, 'JWT 令牌')
            ->addOption('header', 'H', null, '同时显示 JWT Header')
            ->addOption('json', null, null, 'JSON 格式化输出')
            ->setDescription('解码 JWT payload（不验签，仅 Base64 解码）')
            ->setHelp('解码 JWT 令牌的 payload 部分，不进行签名验证');
    }

    protected function execute(Input $input, Output $output): int
    {
        $tokenStr = $input->getArgument('token');
        $showHeader = $input->getOption('header');
        $jsonOutput = $input->getOption('json');

        $jwt = app(Jwt::class);
        $payload = $jwt->decode($tokenStr);

        if ($payload === null) {
            $output->error('令牌格式无效，无法解码');
            return 1;
        }

        // Header
        if ($showHeader) {
            $segments = explode('.', $tokenStr);
            if (count($segments) >= 1) {
                $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $segments[0])), true);
                if ($header) {
                    $output->info('=== Header ===');
                    $output->writeln($jsonOutput ? json_encode($header, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) : $this->formatKV($header));
                    $output->writeln('');
                }
            }
        }

        // Payload
        $output->info('=== Payload（解码，未验证签名） ===');

        if ($jsonOutput) {
            $output->writeln(json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } else {
            $this->printPayloadDetails($output, $payload);
        }

        return 0;
    }

    protected function printPayloadDetails(Output $output, array $payload): void
    {
        // 标准声明
        $standard = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti', 'typ', 'fph', 'ver'];
        $standardLabels = [
            'iss' => '签发者', 'sub' => '用户标识', 'aud' => '受众',
            'iat' => '签发时间', 'nbf' => '生效时间', 'exp' => '过期时间',
            'jti' => 'Token ID', 'typ' => 'Token 类型', 'fph' => '设备指纹',
            'ver' => '版本号',
        ];

        $standardData = [];
        foreach ($standard as $key) {
            if (isset($payload[$key])) {
                $val = $payload[$key];
                if (in_array($key, ['iat', 'nbf', 'exp'], true)) {
                    $val = date('Y-m-d H:i:s', (int) $val) . " ({$val})";
                }
                $standardData[$standardLabels[$key] ?? $key] = $val;
            }
        }

        $this->outputTable($output, $standardData);

        // 自定义声明
        $custom = array_diff_key($payload, array_flip($standard));
        if (!empty($custom)) {
            $output->writeln('');
            $output->comment('自定义声明:');
            $this->outputTable($output, $custom);
        }

        // 状态摘要
        $output->writeln('');
        $now = time();
        if (isset($payload['exp'])) {
            $remaining = (int) $payload['exp'] - $now;
            if ($remaining > 0) {
                $output->writeln("<info>状态: 有效（剩余 {$remaining} 秒，约 " . round($remaining / 3600, 1) . " 小时）</info>");
            } else {
                $output->writeln("<error>状态: 已过期（已过期 " . abs($remaining) . " 秒）</error>");
            }
        }
        if (($payload['typ'] ?? '') === \wise\jwt\Jwt::TYPE_REFRESH) {
            $output->writeln('<comment>类型: Refresh Token</comment>');
        }
    }

    protected function formatKV(array $data): string
    {
        $lines = [];
        foreach ($data as $key => $val) {
            $lines[] = "  {$key}: " . (is_scalar($val) ? $val : json_encode($val, JSON_UNESCAPED_UNICODE));
        }
        return implode("\n", $lines);
    }

    protected function outputTable(Output $output, array $data): void
    {
        foreach ($data as $label => $value) {
            $output->writeln("  <info>{$label}</info>: " . (is_scalar($value) ? $value : json_encode($value, JSON_UNESCAPED_UNICODE)));
        }
    }
}
