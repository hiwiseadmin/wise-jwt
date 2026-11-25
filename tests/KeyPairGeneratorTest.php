<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\signer\KeyPairGenerator;

/**
 * KeyPairGenerator 回归测试
 *
 * 覆盖缺陷：
 * - D-1 `wise:jwt:key:generate -t rsa` 崩溃（openssl_pkey_export 未传 config → 私钥为 null
 *   → str_replace(null) 触发 TypeError）
 * - D-2 `wise:jwt:key:generate -t ec` 同源崩溃
 * - 失败必须抛异常（命令层据此返回非 0 退出码），不得静默返回空值
 */
class KeyPairGeneratorTest extends TestCase
{

    public function test_hmac_returns_64_char_hex_by_default(): void
    {
        $key = KeyPairGenerator::hmac();

        $this->assertSame(64, strlen($key), '默认 32 字节 → 64 位十六进制');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $key);
    }

    public function test_hmac_is_random_between_calls(): void
    {
        $this->assertNotSame(KeyPairGenerator::hmac(), KeyPairGenerator::hmac());
    }

    public function test_hmac_rejects_short_length(): void
    {
        $this->expectException(\RuntimeException::class);

        KeyPairGenerator::hmac(8);
    }


    public function test_rsa_returns_exportable_key_pair(): void
    {
        $keyPair = KeyPairGenerator::rsa(2048);

        $this->assertArrayHasKey('private', $keyPair);
        $this->assertArrayHasKey('public', $keyPair);
        $this->assertStringContainsString('BEGIN PRIVATE KEY', $keyPair['private']);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $keyPair['public']);

        $parsed = openssl_pkey_get_private($keyPair['private']);
        $this->assertNotFalse($parsed, '导出的私钥应可被 openssl_pkey_get_private 解析');

        $details = openssl_pkey_get_details($parsed);
        $this->assertIsArray($details);
        $this->assertSame(2048, $details['bits']);
    }

    public function test_rsa_supports_4096_bits(): void
    {
        $keyPair = KeyPairGenerator::rsa(4096);
        $details = openssl_pkey_get_details(openssl_pkey_get_private($keyPair['private']));

        $this->assertSame(4096, $details['bits']);
    }


    public function test_ec_returns_exportable_key_pair(): void
    {
        $keyPair = KeyPairGenerator::ec();

        $this->assertStringContainsString('BEGIN PRIVATE KEY', $keyPair['private']);
        $this->assertStringContainsString('BEGIN PUBLIC KEY', $keyPair['public']);

        $parsed = openssl_pkey_get_private($keyPair['private']);
        $this->assertNotFalse($parsed);

        $details = openssl_pkey_get_details($parsed);
        $this->assertSame(OPENSSL_KEYTYPE_EC, $details['type']);
        $this->assertSame(256, $details['bits'], '默认 prime256v1 → 256 位');
    }

    public function test_ec_supports_p384_curve(): void
    {
        $keyPair = KeyPairGenerator::ec('secp384r1');
        $details = openssl_pkey_get_details(openssl_pkey_get_private($keyPair['private']));

        $this->assertSame(384, $details['bits']);
    }

    public function test_ec_throws_on_unknown_curve(): void
    {
        $this->expectException(\RuntimeException::class);

        KeyPairGenerator::ec('not-a-real-curve');
    }


    public function test_eddsa_throws_when_sodium_missing(): void
    {
        if (function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('当前环境已安装 sodium，无法覆盖缺失分支');
        }

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessageMatches('/sodium/');

        KeyPairGenerator::eddsa();
    }

    public function test_eddsa_returns_hex_key_pair_when_available(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('当前环境未安装 sodium');
        }

        $keyPair = KeyPairGenerator::eddsa();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $keyPair['private']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $keyPair['public']);
    }
}
