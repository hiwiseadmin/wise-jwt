<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Jwt;
use wise\jwt\Builder;
use wise\jwt\Payload;
use wise\jwt\signer\HS256Signer;
use wise\jwt\validator\Validator;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\TokenExpiredException;
use wise\jwt\exception\TokenInvalidException;
use wise\jwt\exception\SignatureInvalidException;

class CoreTest extends TestCase
{
    protected Jwt $jwt;

    protected function setUp(): void
    {
        $signer = new HS256Signer('test-secret-key-32bytes-long!!');
        $validator = new Validator(0);
        $this->jwt = new Jwt(
            algorithm: 'HS256',
            signer: $signer,
            validator: $validator,
            blacklist: null,
            issuer: 'test-issuer',
            ttl: 3600,
            refreshTtl: 1800
        );
    }

    /** 测试签发+解析往返 */
    public function testIssueAndParseRoundtrip(): void
    {
        $token = $this->jwt->issue('user-123', ['role' => 'admin']);
        $this->assertIsString($token);
        $this->assertMatchesRegularExpression('/^[\w\-]+\.[\w\-]+\.[\w\-]+$/', $token);

        $payload = $this->jwt->parse($token);
        $this->assertEquals('test-issuer', $payload['iss']);
        $this->assertEquals('user-123', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
        $this->assertArrayHasKey('iat', $payload);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('jti', $payload);
    }

    /** 测试无效 token 被拒 */
    public function testParseInvalidTokenThrowsException(): void
    {
        $this->expectException(JwtException::class);
        $this->jwt->parse('invalid.token.here');
    }

    /** 测试格式错误 token */
    public function testParseMalformedToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->jwt->parse('only.two.segments.extra');
    }

    /** 测试签名被篡改 */
    public function testTamperedSignatureFails(): void
    {
        $token = $this->jwt->issue('user-1');
        // 篡改 payload 部分
        $parts = explode('.', $token);
        $parts[1] = base64_encode(json_encode(['sub' => 'hacker']));
        $tampered = implode('.', $parts);

        $this->expectException(SignatureInvalidException::class);
        $this->jwt->parse($tampered);
    }

    /** 测试 tryParse 安全模式 */
    public function testTryParseReturnsNullOnFailure(): void
    {
        $this->assertNull($this->jwt->tryParse('invalid'));
        $this->assertNull($this->jwt->tryParse('a.b.c'));

        $token = $this->jwt->issue('user-1');
        $this->assertIsArray($this->jwt->tryParse($token));
    }

    /** 测试 ttlOf */
    public function testTtlOf(): void
    {
        $token = $this->jwt->issue('user-1');
        $payload = $this->jwt->parse($token);
        $ttl = $this->jwt->ttlOf($payload);
        $this->assertGreaterThan(0, $ttl);
        $this->assertLessThanOrEqual(3600, $ttl);
    }

    /** 测试 shouldRefresh */
    public function testShouldRefresh(): void
    {
        // 当前 token 还有很长时间才过期，不应续签
        $token = $this->jwt->issue('user-1');
        $payload = $this->jwt->parse($token);
        $this->assertFalse($this->jwt->shouldRefresh($payload));

        // 模拟即将过期的 payload
        $nearExpirePayload = ['exp' => time() + 60]; // 60秒后过期，refreshTtl=1800
        $this->assertTrue($this->jwt->shouldRefresh($nearExpirePayload));
    }

    /** 测试 refresh() */
    public function testRefresh(): void
    {
        // ttl=60s 使其落入续签窗口（refreshTtl=1800），否则 refresh() 会拒绝
        $token = $this->jwt->issue('user-1', ['role' => 'user'], 60);
        $newToken = $this->jwt->refresh($token);

        $this->assertNotEquals($token, $newToken);
        $payload = $this->jwt->parse($newToken);
        $this->assertEquals('user-1', $payload['sub']);
        $this->assertEquals('user', $payload['role']);
    }

    /** 测试标准声明不可被自定义 claims 覆盖 */
    public function testStandardClaimsCannotBeOverridden(): void
    {
        $token = $this->jwt->issue('user-1', [
            'sub'  => 'hacker',
            'iss'  => 'evil',
            'exp'  => time() + 999999,
            'jti'  => 'fixed-jti',
            'role' => 'admin',
        ]);

        $payload = $this->jwt->parse($token);

        $this->assertEquals('user-1', $payload['sub']);
        $this->assertEquals('test-issuer', $payload['iss']);
        $this->assertLessThanOrEqual(time() + 3600, $payload['exp']);
        $this->assertNotEquals('fixed-jti', $payload['jti']);
        $this->assertEquals('admin', $payload['role']); // 非保留声明仍生效
    }

    /** 测试 getAlgorithm / getIssuer */
    public function testGetters(): void
    {
        $this->assertEquals('HS256', $this->jwt->getAlgorithm());
        $this->assertEquals('test-issuer', $this->jwt->getIssuer());
    }
}
