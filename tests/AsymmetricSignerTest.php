<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Jwt;
use wise\jwt\TokenPair;
use wise\jwt\signer\RS256Signer;
use wise\jwt\signer\RS384Signer;
use wise\jwt\signer\RS512Signer;
use wise\jwt\signer\ES256Signer;
use wise\jwt\signer\ES384Signer;
use wise\jwt\signer\ES512Signer;
use wise\jwt\signer\EdDSASigner;
use wise\jwt\signer\SignerFactory;
use wise\jwt\validator\Validator;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\SignatureInvalidException;

/**
 * RSA / ECDSA / EdDSA 签名器全面测试
 * - 签发+验签往返
 * - 密钥空值校验
 * - 错误密钥拒绝
 * - 算法不匹配攻击
 * - EdDSA seed 自动转换
 * - SignerFactory 工厂测试
 */
class AsymmetricSignerTest extends TestCase
{
    /** @var string[] */
    private static array $rsaKeys = [];
    private static array $ecKeys = [];
    private static string $edPrivateKey = '';
    private static string $edPublicKey = '';

    public static function setUpBeforeClass(): void
    {
        // 生成 RSA 密钥对
        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $rsaRes = openssl_pkey_new($config);
        if ($rsaRes) {
            openssl_pkey_export($rsaRes, self::$rsaKeys['private']);
            self::$rsaKeys['public'] = openssl_pkey_get_details($rsaRes)['key'];
        }

        // 生成 EC P-256 密钥对
        $ecConfig = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        $ecRes = openssl_pkey_new($ecConfig);
        if ($ecRes) {
            openssl_pkey_export($ecRes, self::$ecKeys['private']);
            self::$ecKeys['public'] = openssl_pkey_get_details($ecRes)['key'];
        }

        // EdDSA
        if (function_exists('sodium_crypto_sign_keypair')) {
            $kp = sodium_crypto_sign_keypair();
            self::$edPrivateKey = sodium_bin2hex(sodium_crypto_sign_secretkey($kp));
            self::$edPublicKey = sodium_bin2hex(sodium_crypto_sign_publickey($kp));
        }
    }

    // ── RSA ──

    public function testRs256SignAndVerify(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = new RS256Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS256', $signer, new Validator(0));

        $token = $jwt->issue('user-1', ['role' => 'admin']);
        $payload = $jwt->parse($token);

        $this->assertEquals('user-1', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
    }

    public function testRs384Roundtrip(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = new RS384Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS384', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testRs512Roundtrip(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = new RS512Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS512', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testRsaTamperedTokenRejected(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = new RS256Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS256', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $parts = explode('.', $token);
        $parts[1] = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode(['sub' => 'hacker'])));
        $tampered = implode('.', $parts);

        $this->expectException(SignatureInvalidException::class);
        $jwt->parse($tampered);
    }

    // ── ECDSA ──

    public function testEs256Roundtrip(): void
    {
        if (empty(self::$ecKeys)) {
            $this->markTestSkipped('OpenSSL EC 不可用');
        }

        $signer = new ES256Signer(self::$ecKeys['private'], self::$ecKeys['public']);
        $jwt = new Jwt('ES256', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testEs384Roundtrip(): void
    {
        if (empty(self::$ecKeys)) {
            $this->markTestSkipped('OpenSSL EC 不可用');
        }

        $signer = new ES384Signer(self::$ecKeys['private'], self::$ecKeys['public']);
        $jwt = new Jwt('ES384', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testEs512Roundtrip(): void
    {
        if (empty(self::$ecKeys)) {
            $this->markTestSkipped('OpenSSL EC 不可用');
        }

        $signer = new ES512Signer(self::$ecKeys['private'], self::$ecKeys['public']);
        $jwt = new Jwt('ES512', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    // ── EdDSA ──

    public function testEddsaRoundtrip(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair') || empty(self::$edPrivateKey)) {
            $this->markTestSkipped('Sodium 扩展不可用');
        }

        $signer = new EdDSASigner(self::$edPrivateKey, self::$edPublicKey);
        $jwt = new Jwt('EdDSA', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    // ── 双令牌 + 非对称 ──

    public function testRs256IssuePair(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = new RS256Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS256', $signer, new Validator(0));

        $pair = $jwt->issuePair('user-1', ['role' => 'admin']);
        $this->assertInstanceOf(TokenPair::class, $pair);
        $this->assertNotEmpty($pair->accessToken);
        $this->assertNotEmpty($pair->refreshToken);

        $atPayload = $jwt->parse($pair->accessToken);
        $rtPayload = $jwt->parse($pair->refreshToken);
        $this->assertEquals('user-1', $atPayload['sub']);
        $this->assertEquals('refresh', $rtPayload['typ'] ?? '');
    }

    // ────────────────────────────────────────────
    //  密钥校验测试（空密钥应在构造时立即报错）
    // ────────────────────────────────────────────

    public function testRsaConstructorRejectsEmptyPrivateKey(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('RS256 私钥不能为空');
        new RS256Signer('', 'not-empty');
    }

    public function testRsaConstructorRejectsEmptyPublicKey(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('RS256 公钥不能为空');
        new RS256Signer('not-empty', '');
    }

    public function testEcConstructorRejectsEmptyPrivateKey(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('ES256 私钥不能为空');
        new ES256Signer('', 'not-empty');
    }

    public function testEcConstructorRejectsEmptyPublicKey(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('ES256 公钥不能为空');
        new ES256Signer('not-empty', '');
    }

    public function testEddsaConstructorRejectsEmptyKeys(): void
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Sodium 扩展不可用');
        }

        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('EdDSA 私钥不能为空');
        new EdDSASigner('', 'not-empty');
    }

    // ────────────────────────────────────────────
    //  错误密钥测试
    // ────────────────────────────────────────────

    public function testRsaSignWithA_VerifyWithB_ShouldFail(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $altRes = openssl_pkey_new($config);
        openssl_pkey_export($altRes, $altPrivate);
        $altPublic = openssl_pkey_get_details($altRes)['key'];

        $signerA = new RS256Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS256', $signerA, new Validator(0));
        $token = $jwt->issue('user-1');

        $signerB = new RS256Signer($altPrivate, $altPublic);
        $jwtB = new Jwt('RS256', $signerB, new Validator(0));

        $this->expectException(SignatureInvalidException::class);
        $jwtB->parse($token);
    }

    public function testEcSignWithA_VerifyWithB_ShouldFail(): void
    {
        if (empty(self::$ecKeys)) {
            $this->markTestSkipped('OpenSSL EC 不可用');
        }

        $ecConfig = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        $altRes = openssl_pkey_new($ecConfig);
        if (!$altRes) {
            $this->markTestSkipped('无法生成备用 EC 密钥');
        }
        openssl_pkey_export($altRes, $altPrivate);
        $altPublic = openssl_pkey_get_details($altRes)['key'];

        $signerA = new ES256Signer(self::$ecKeys['private'], self::$ecKeys['public']);
        $jwt = new Jwt('ES256', $signerA, new Validator(0));
        $token = $jwt->issue('user-1');

        $signerB = new ES256Signer($altPrivate, $altPublic);
        $jwtB = new Jwt('ES256', $signerB, new Validator(0));

        $this->expectException(SignatureInvalidException::class);
        $jwtB->parse($token);
    }

    // ────────────────────────────────────────────
    //  算法不匹配攻击测试
    // ────────────────────────────────────────────

    public function testAlgorithmMismatchInHeaderThrowsException(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = new RS256Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $jwt = new Jwt('RS256', $signer, new Validator(0));
        $token = $jwt->issue('user-1');

        $parts = explode('.', $token);
        $header = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[0])), true);
        $header['alg'] = 'HS256';
        $parts[0] = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode($header)));
        $tampered = implode('.', $parts);

        $this->expectException(SignatureInvalidException::class);
        $this->expectExceptionMessage('算法不匹配');
        $jwt->parse($tampered);
    }

    public function testCrossAlgorithmTokenRejected(): void
    {
        if (empty(self::$rsaKeys) || empty(self::$ecKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $rsaSigner = new RS256Signer(self::$rsaKeys['private'], self::$rsaKeys['public']);
        $rsaJwt = new Jwt('RS256', $rsaSigner, new Validator(0));
        $token = $rsaJwt->issue('user-1');

        $ecSigner = new ES256Signer(self::$ecKeys['private'], self::$ecKeys['public']);
        $ecJwt = new Jwt('ES256', $ecSigner, new Validator(0));

        $this->expectException(SignatureInvalidException::class);
        $ecJwt->parse($token);
    }

    // ────────────────────────────────────────────
    //  EdDSA seed 自动转换测试
    // ────────────────────────────────────────────

    public function testEddsaAccepts64ByteSecretKey(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('Sodium 扩展不可用');
        }

        $keypair = sodium_crypto_sign_keypair();
        $sk64 = sodium_crypto_sign_secretkey($keypair);
        $pk = sodium_crypto_sign_publickey($keypair);

        $signer = new EdDSASigner(sodium_bin2hex($sk64), sodium_bin2hex($pk));
        $this->assertEquals('EdDSA', $signer->algorithm());

        $jwt = new Jwt('EdDSA', $signer, new Validator(0));
        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testEddsaBase64EncodedKeyWorks(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            $this->markTestSkipped('Sodium 扩展不可用');
        }

        $keypair = sodium_crypto_sign_keypair();
        $sk64 = sodium_crypto_sign_secretkey($keypair);
        $pk = sodium_crypto_sign_publickey($keypair);

        $signer = new EdDSASigner(base64_encode($sk64), base64_encode($pk));
        $jwt = new Jwt('EdDSA', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $payload = $jwt->parse($token);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testEddsaEd25519TamperedTokenRejected(): void
    {
        if (!function_exists('sodium_crypto_sign_keypair') || empty(self::$edPrivateKey)) {
            $this->markTestSkipped('Sodium 扩展不可用');
        }

        $signer = new EdDSASigner(self::$edPrivateKey, self::$edPublicKey);
        $jwt = new Jwt('EdDSA', $signer, new Validator(0));

        $token = $jwt->issue('user-1');
        $parts = explode('.', $token);
        $parts[1] = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode(['sub' => 'hacker'])));
        $tampered = implode('.', $parts);

        $this->expectException(SignatureInvalidException::class);
        $jwt->parse($tampered);
    }

    // ────────────────────────────────────────────
    //  SignerFactory 测试
    // ────────────────────────────────────────────

    public function testSignerFactoryCreatesCorrectSigner(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = SignerFactory::create('RS256', [
            'private_key' => self::$rsaKeys['private'],
            'public_key'  => self::$rsaKeys['public'],
        ]);

        $this->assertInstanceOf(RS256Signer::class, $signer);
        $this->assertEquals('RS256', $signer->algorithm());
    }

    public function testSignerFactoryRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('不支持的算法');
        SignerFactory::create('UNKNOWN', []);
    }

    public function testSignerFactoryCaseInsensitiveAlgorithm(): void
    {
        if (empty(self::$rsaKeys)) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $signer = SignerFactory::create('rs256', [
            'private_key' => self::$rsaKeys['private'],
            'public_key'  => self::$rsaKeys['public'],
        ]);

        $this->assertInstanceOf(RS256Signer::class, $signer);
    }
}
