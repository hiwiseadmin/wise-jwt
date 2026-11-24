<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use wise\jwt\exception\JwtException;
use wise\jwt\signer\JwkConverter;
use wise\support\crypto\OpenSslConfig;

/**
 * JWK ↔ PEM 转换回归测试
 *
 * 背景：`jwkToPublicKey()` 此前对 RSA / EC 全部失败——打包出的 ASN.1 结构非法
 * （RSA 缺少 RSAPublicKey SEQUENCE 且长度字段算错；EC 硬编码了 P-256 的长度），
 * 并且对公钥误用 `openssl_pkey_export()`（该函数仅用于导出私钥，返回 false 且不写出
 * `$output`）。这两处缺陷叠加导致该 API 自始至终不可用，且此前无任何测试覆盖。
 *
 * 本用例锁定：JWK 往返后的公钥与原公钥等价、异常契约（JwtException 而非 TypeError）。
 */
class JwkConverterTest extends TestCase
{
    private static string $rsaPublic = '';

    public static function setUpBeforeClass(): void
    {
        if (!function_exists('openssl_pkey_new')) {
            return;
        }

        $res = openssl_pkey_new(OpenSslConfig::withConfig([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]));
        if ($res) {
            self::$rsaPublic = (string) (openssl_pkey_get_details($res)['key'] ?? '');
        }
    }

    public function testRsaJwkRoundTrip(): void
    {
        if (self::$rsaPublic === '') {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $jwk = JwkConverter::publicKeyToJwk(self::$rsaPublic, 'rsa-1');
        $this->assertSame('RSA', $jwk['kty']);
        $this->assertSame('rsa-1', $jwk['kid']);
        $this->assertNotEmpty($jwk['n']);
        $this->assertNotEmpty($jwk['e']);

        $pem = JwkConverter::jwkToPublicKey($jwk);

        $this->assertNotSame('', $pem, 'jwkToPublicKey() 必须返回非空 PEM');
        $this->assertNotFalse(openssl_pkey_get_public($pem), '输出的 PEM 必须可被 OpenSSL 解析');
        $this->assertSame(
            self::normalize(self::$rsaPublic),
            self::normalize($pem),
            'JWK 往返后的公钥必须与原公钥一致'
        );
    }

    #[DataProvider('ecCurveProvider')]
    public function testEcJwkRoundTrip(string $curveName, string $expectedCrv): void
    {
        if (!function_exists('openssl_pkey_new')) {
            $this->markTestSkipped('OpenSSL 不可用');
        }

        $res = openssl_pkey_new(OpenSslConfig::withConfig([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => $curveName,
        ]));
        if (!$res) {
            $this->markTestSkipped("OpenSSL 不支持曲线 {$curveName}");
        }

        $public = (string) (openssl_pkey_get_details($res)['key'] ?? '');
        $jwk = JwkConverter::publicKeyToJwk($public);

        $this->assertSame('EC', $jwk['kty']);
        $this->assertSame($expectedCrv, $jwk['crv']);

        $pem = JwkConverter::jwkToPublicKey($jwk);

        $this->assertNotSame('', $pem, 'jwkToPublicKey() 必须返回非空 PEM');
        $this->assertNotFalse(openssl_pkey_get_public($pem), "{$expectedCrv} 输出的 PEM 必须可被 OpenSSL 解析");
        $this->assertSame(
            self::normalize($public),
            self::normalize($pem),
            "{$expectedCrv} JWK 往返后的公钥必须与原公钥一致"
        );
    }

    public static function ecCurveProvider(): array
    {
        return [
            'P-256' => ['prime256v1', 'P-256'],
            'P-384' => ['secp384r1', 'P-384'],
            'P-521' => ['secp521r1', 'P-521'],
        ];
    }

    /**
     * 非法 PEM 必须抛 JwtException（此前因把 false 传给 openssl_pkey_get_details() 而抛 TypeError）
     */
    public function testPublicKeyToJwkRejectsInvalidPem(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('无法解析 PEM 公钥');

        JwkConverter::publicKeyToJwk("-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----");
    }

    public function testJwkToPublicKeyRejectsUnsupportedKty(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('不支持的 JWK 类型');

        JwkConverter::jwkToPublicKey(['kty' => 'OKP', 'crv' => 'Ed25519']);
    }

    public function testJwkToPublicKeyRejectsMissingKty(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('JWK 缺少 kty 字段');

        JwkConverter::jwkToPublicKey([]);
    }

    public function testRsaJwkRequiresModulusAndExponent(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('RSA JWK 缺少 n 或 e 字段');

        JwkConverter::jwkToPublicKey(['kty' => 'RSA', 'n' => 'AQAB']);
    }

    /**
     * 去掉 PEM 头尾与空白，便于比较两份 PEM 的 DER 是否一致
     */
    private static function normalize(string $pem): string
    {
        return (string) preg_replace('/-----[^-]+-----|\s+/', '', $pem);
    }
}
