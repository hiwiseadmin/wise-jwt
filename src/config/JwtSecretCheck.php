<?php
declare(strict_types=1);

namespace wise\jwt\config;

use wise\support\config\CheckLevel;
use wise\support\config\CheckResult;
use wise\support\config\ConfigCheckInterface;

/**
 * wise-jwt 密钥配置检测
 *
 * 检测 HS/RS/ES 算法的密钥是否配置（支持 direct / base64 / file 三种形式）。
 */
class JwtSecretCheck implements ConfigCheckInterface
{
    public function __construct(
        private readonly \think\Config $config,
    ) {
    }

    public function id(): string
    {
        return 'wise-jwt:secret';
    }

    public function package(): string
    {
        return 'wise-jwt';
    }

    public function level(): CheckLevel
    {
        return CheckLevel::ERROR;
    }

    public function check(): CheckResult
    {
        $algorithm = strtoupper((string) $this->config->get('wise-jwt.algorithm', 'HS256'));

        if (str_starts_with($algorithm, 'HS')) {
            return $this->checkHmacSecret();
        }

        return $this->checkAsymmetricKeys();
    }

    private function checkHmacSecret(): CheckResult
    {
        $secret = (string) $this->config->get('wise-jwt.secret', '');
        $base64 = (string) $this->config->get('wise-jwt.secret_base64', '');
        $file   = (string) $this->config->get('wise-jwt.secret_file', '');

        if ($secret === '' && $base64 === '' && $file === '') {
            return CheckResult::fail(
                'HS 算法密钥未配置',
                '请在 .env 中设置 JWT_SECRET / JWT_SECRET_BASE64 / JWT_SECRET_FILE'
            );
        }

        return CheckResult::ok();
    }

    private function checkAsymmetricKeys(): CheckResult
    {
        $privateKey   = (string) $this->config->get('wise-jwt.private_key', '');
        $privateBase64 = (string) $this->config->get('wise-jwt.private_key_base64', '');
        $privateFile   = (string) $this->config->get('wise-jwt.private_key_file', '');

        $publicKey   = (string) $this->config->get('wise-jwt.public_key', '');
        $publicBase64 = (string) $this->config->get('wise-jwt.public_key_base64', '');
        $publicFile   = (string) $this->config->get('wise-jwt.public_key_file', '');

        $hasPrivate = $privateKey !== '' || $privateBase64 !== '' || $privateFile !== '';
        $hasPublic  = $publicKey !== '' || $publicBase64 !== '' || $publicFile !== '';

        if (!$hasPrivate) {
            return CheckResult::fail(
                '非对称算法私钥未配置',
                '请在 .env 中设置 JWT_PRIVATE_KEY / JWT_PRIVATE_KEY_BASE64 / JWT_PRIVATE_KEY_FILE'
            );
        }

        if (!$hasPublic) {
            return CheckResult::fail(
                '非对称算法公钥未配置',
                '请在 .env 中设置 JWT_PUBLIC_KEY / JWT_PUBLIC_KEY_BASE64 / JWT_PUBLIC_KEY_FILE'
            );
        }

        return CheckResult::ok();
    }
}
