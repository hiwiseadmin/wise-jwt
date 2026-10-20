<?php
declare(strict_types=1);

namespace wise\jwt\command;

use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\console\input\Option;
use wise\support\crypto\OpenSslConfig;

/**
 * 生成 JWT 密钥对
 *
 * 用法：
 *   php think wise:jwt:key:generate                     # 生成 HMAC 密钥
 *   php think wise:jwt:key:generate --type=rsa          # 生成 RSA 密钥对
 *   php think wise:jwt:key:generate --type=ec           # 生成 ECDSA 密钥对
 *   php think wise:jwt:key:generate --type=eddsa        # 生成 EdDSA 密钥对
 */
class KeyGenerate extends Command
{
    protected function configure(): void
    {
        $this->setName('wise:jwt:key:generate')
            ->addOption('type', 't', Option::VALUE_REQUIRED, '密钥类型: hmac|rsa|ec|eddsa', 'hmac')
            ->addOption('bits', 'b', Option::VALUE_REQUIRED, '密钥长度（RSA:2048/4096, EC:256/384）', '2048')
            ->addOption('output', 'o', Option::VALUE_NONE, '输出适用于 config/wise-jwt.php 的配置格式')
            ->setDescription('生成 JWT 签名密钥')
            ->setHelp('生成 JWT 签名密钥，支持 HMAC/RSA/ECDSA/EdDSA');
    }

    protected function execute(Input $input, Output $output): int
    {
        $type = strtolower($input->getOption('type'));
        $bits = (int) $input->getOption('bits');
        $envFormat = $input->getOption('output');

        switch ($type) {
            case 'hmac':
                $this->generateHmac($output, $envFormat);
                break;
            case 'rsa':
                $this->generateRsa($output, $bits, $envFormat);
                break;
            case 'ec':
                $this->generateEc($output, $envFormat);
                break;
            case 'eddsa':
                $this->generateEdDsa($output, $envFormat);
                break;
            default:
                $output->error("不支持的密钥类型: {$type}，支持: hmac|rsa|ec|eddsa");
                return 1;
        }

        return 0;
    }

    protected function generateHmac(Output $output, bool $envFormat): void
    {
        $key = bin2hex(random_bytes(32));
        $output->info("=== HMAC 密钥（HS256/HS384/HS512） ===");

        if ($envFormat) {
            $output->writeln("JWT_ALGORITHM=HS256");
            $output->writeln("JWT_SECRET={$key}");
        } else {
            $output->writeln("算法: HS256 / HS384 / HS512");
            $output->writeln("密钥: {$key}");
        }

        $output->writeln('');
        $output->comment("请将密钥保存到 config/wise-jwt.php 的 secret 字段");
    }

    protected function generateRsa(Output $output, int $bits, bool $envFormat): void
    {
        if (!in_array($bits, [2048, 4096], true)) {
            $output->warning("建议使用 2048 或 4096 位，当前: {$bits}");
        }

        $config = OpenSslConfig::withConfig([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $res = openssl_pkey_new($config);
        if (!$res) {
            $output->error('生成 RSA 密钥对失败');
            return;
        }

        openssl_pkey_export($res, $privateKey);
        $publicKey = openssl_pkey_get_details($res)['key'];

        $privateKeyOneLine = str_replace("\n", "\\n", $privateKey);
        $publicKeyOneLine = str_replace("\n", "\\n", $publicKey);

        $output->info("=== RSA 密钥对（RS256/RS384/RS512） ===");

        if ($envFormat) {
            $output->writeln("JWT_ALGORITHM=RS256");
            $output->writeln("JWT_PRIVATE_KEY={$privateKeyOneLine}");
            $output->writeln("JWT_PUBLIC_KEY={$publicKeyOneLine}");
        } else {
            $output->writeln("算法: RS256 / RS384 / RS512");
            $output->writeln("===== 私钥 =====");
            $output->writeln($privateKey);
            $output->writeln("===== 公钥 =====");
            $output->writeln($publicKey);
        }

        $output->writeln('');
        $output->comment("请将密钥保存到 config/wise-jwt.php 的 private_key/public_key 字段");
    }

    protected function generateEc(Output $output, bool $envFormat): void
    {
        $config = OpenSslConfig::withConfig([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => 'prime256v1',
        ]);

        $res = openssl_pkey_new($config);
        if (!$res) {
            $output->error('生成 ECDSA 密钥对失败');
            return;
        }

        openssl_pkey_export($res, $privateKey);
        $publicKey = openssl_pkey_get_details($res)['key'];

        $privateKeyOneLine = str_replace("\n", "\\n", $privateKey);
        $publicKeyOneLine = str_replace("\n", "\\n", $publicKey);

        $output->info("=== ECDSA 密钥对（ES256/ES384/ES512） ===");

        if ($envFormat) {
            $output->writeln("JWT_ALGORITHM=ES256");
            $output->writeln("JWT_PRIVATE_KEY={$privateKeyOneLine}");
            $output->writeln("JWT_PUBLIC_KEY={$publicKeyOneLine}");
        } else {
            $output->writeln("算法: ES256 / ES384 / ES512 (P-256 curve)");
            $output->writeln("===== 私钥 =====");
            $output->writeln($privateKey);
            $output->writeln("===== 公钥 =====");
            $output->writeln($publicKey);
        }

        $output->writeln('');
        $output->comment("请将密钥保存到 config/wise-jwt.php 的 private_key/public_key 字段");
    }

    protected function generateEdDsa(Output $output, bool $envFormat): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $output->error('EdDSA 需要 sodium 扩展，当前环境未安装');
            return;
        }

        $keypair = sodium_crypto_sign_keypair();
        $privateKey = sodium_bin2hex(sodium_crypto_sign_secretkey($keypair));
        $publicKey = sodium_bin2hex(sodium_crypto_sign_publickey($keypair));

        $output->info("=== EdDSA 密钥对（Ed25519） ===");

        if ($envFormat) {
            $output->writeln("JWT_ALGORITHM=EdDSA");
            $output->writeln("JWT_PRIVATE_KEY={$privateKey}");
            $output->writeln("JWT_PUBLIC_KEY={$publicKey}");
        } else {
            $output->writeln("算法: EdDSA (Ed25519)");
            $output->writeln("私钥 (hex): {$privateKey}");
            $output->writeln("公钥 (hex): {$publicKey}");
        }

        $output->writeln('');
        $output->comment("请将密钥保存到 config/wise-jwt.php 的 private_key/public_key 字段");
    }
}
