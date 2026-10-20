<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Jwt;
use wise\jwt\TokenPair;
use wise\jwt\signer\HS256Signer;
use wise\jwt\validator\Validator;
use wise\jwt\blacklist\CacheBlacklist;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\TokenInvalidException;
use wise\jwt\exception\BlacklistedException;
use wise\jwt\exception\SignatureInvalidException;

/**
 * 双令牌模式测试：issuePair / refreshAccessToken / revokeRefreshToken / decode
 */
class JwtDualTokenTest extends TestCase
{
    protected Jwt $jwt;
    protected CacheBlacklist $blacklist;

    protected function setUp(): void
    {
        $this->blacklist = new CacheBlacklist('test:bl:');
        $this->jwt = new Jwt(
            algorithm: 'HS256',
            signer: new HS256Signer('test-secret-32bytes-long!!'),
            validator: new Validator(0),
            blacklist: $this->blacklist,
            issuer: 'test-issuer',
            ttl: 3600,
            refreshTtl: 1800,
            audience: null,
            refreshTokenTtl: 86400,
            refreshTokenRotation: true,
            refreshTokenFingerprint: false
        );
    }

    /** @test 签发 Token 对 */
    public function testIssuePair(): void
    {
        $pair = $this->jwt->issuePair('user-123', ['role' => 'admin']);

        $this->assertInstanceOf(TokenPair::class, $pair);
        $this->assertNotEmpty($pair->accessToken);
        $this->assertNotEmpty($pair->refreshToken);
        $this->assertNotEquals($pair->accessToken, $pair->refreshToken);
        $this->assertEquals('Bearer', $pair->tokenType);
        $this->assertEquals(3600, $pair->expiresIn);
        $this->assertEquals(86400, $pair->refreshExpiresIn);
    }

    /** @test Access Token 可正常解析 */
    public function testAccessTokenCanBeParsed(): void
    {
        $pair = $this->jwt->issuePair('user-123', ['role' => 'admin']);
        $payload = $this->jwt->parse($pair->accessToken);

        $this->assertEquals('user-123', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
        $this->assertArrayNotHasKey('typ', $payload); // Access token 无 typ
    }

    /** @test Refresh Token 标记为 refresh 类型 */
    public function testRefreshTokenHasTypeClaim(): void
    {
        $pair = $this->jwt->issuePair('user-123');
        $payload = $this->jwt->parse($pair->refreshToken);

        $this->assertEquals('refresh', $payload['typ'] ?? '');
        $this->assertEquals('user-123', $payload['sub']);
    }

    /** @test Refresh Token 有效期长于 Access Token */
    public function testRefreshTokenHasLongerTtl(): void
    {
        $pair = $this->jwt->issuePair('user-123');
        $atPayload = $this->jwt->parse($pair->accessToken);
        $rtPayload = $this->jwt->parse($pair->refreshToken);

        $atTtl = $atPayload['exp'] - $atPayload['iat'];
        $rtTtl = $rtPayload['exp'] - $rtPayload['iat'];

        $this->assertGreaterThan($atTtl, $rtTtl);
    }

    /** @test 自定义 access/refresh TTL */
    public function testCustomTtls(): void
    {
        $pair = $this->jwt->issuePair('user-1', [], 1800, 3600);

        $this->assertEquals(1800, $pair->expiresIn);
        $this->assertEquals(3600, $pair->refreshExpiresIn);
    }

    /** @test 使用 Refresh Token 刷新获取新 Token 对 */
    public function testRefreshAccessTokenReturnsNewPair(): void
    {
        $pair = $this->jwt->issuePair('user-123', ['role' => 'admin']);
        $newPair = $this->jwt->refreshAccessToken($pair->refreshToken);

        $this->assertInstanceOf(TokenPair::class, $newPair);
        $this->assertNotEmpty($newPair->accessToken);
        $this->assertNotEmpty($newPair->refreshToken);

        // 新 token 不应与旧 token 相同
        $this->assertNotEquals($pair->accessToken, $newPair->accessToken);
        $this->assertNotEquals($pair->refreshToken, $newPair->refreshToken);

        // 新 access token 可解析，保留自定义声明
        $payload = $this->jwt->parse($newPair->accessToken);
        $this->assertEquals('user-123', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
    }

    /** @test Refresh Token Rotation：旧 token 被吊销，新 token 可用 */
    public function testRefreshTokenRotationRevokesOldToken(): void
    {
        $pair = $this->jwt->issuePair('user-123');
        $this->jwt->refreshAccessToken($pair->refreshToken);

        // 旧 Refresh Token 应被吊销
        $this->expectException(BlacklistedException::class);
        $this->jwt->parse($pair->refreshToken);
    }

    /** @test Refresh Token Replay 检测 */
    public function testRefreshTokenReplayDetection(): void
    {
        $pair = $this->jwt->issuePair('user-123');
        $this->jwt->refreshAccessToken($pair->refreshToken);

        // 二次使用相同的 Refresh Token → replay attack → 抛出 BlacklistedException
        $this->expectException(BlacklistedException::class);
        $this->jwt->refreshAccessToken($pair->refreshToken);
    }

    /** @test 用 Access Token 调用 refreshAccessToken 应失败 */
    public function testRefreshAccessTokenRejectsAccessToken(): void
    {
        $pair = $this->jwt->issuePair('user-123');

        $this->expectException(TokenInvalidException::class);
        $this->jwt->refreshAccessToken($pair->accessToken);
    }

    /** @test 自定义声明在刷新时保留并可覆盖 */
    public function testCustomClaimsPreservedOnRefresh(): void
    {
        $pair = $this->jwt->issuePair('user-123', ['role' => 'user', 'dept' => 'sales']);
        $newPair = $this->jwt->refreshAccessToken($pair->refreshToken, ['role' => 'manager']);

        $payload = $this->jwt->parse($newPair->accessToken);
        $this->assertEquals('manager', $payload['role']);   // 被覆盖
        $this->assertEquals('sales', $payload['dept']);      // 保留
    }

    /** @test 吊销 Refresh Token */
    public function testRevokeRefreshToken(): void
    {
        $pair = $this->jwt->issuePair('user-123');
        $this->assertTrue($this->jwt->revokeRefreshToken($pair->refreshToken));

        $this->expectException(BlacklistedException::class);
        $this->jwt->parse($pair->refreshToken);
    }

    /** @test 用 Access Token 调用 revokeRefreshToken 返回 false */
    public function testRevokeRefreshTokenWithAccessToken(): void
    {
        $pair = $this->jwt->issuePair('user-123');
        $this->assertFalse($this->jwt->revokeRefreshToken($pair->accessToken));
    }

    /** @test decode 仅解码不验签 */
    public function testDecode(): void
    {
        $token = $this->jwt->issue('user-1', ['role' => 'admin']);
        $payload = $this->jwt->decode($token);

        $this->assertIsArray($payload);
        $this->assertEquals('user-1', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
    }

    /** @test decode 对无效格式返回 null */
    public function testDecodeInvalidToken(): void
    {
        $this->assertNull($this->jwt->decode('not.a.token'));
        $this->assertNull($this->jwt->decode(''));
        $this->assertNull($this->jwt->decode('only'));
    }

    /** @test decode 不检查签名（篡改的 token 也能解码） */
    public function testDecodeIgnoresSignature(): void
    {
        $token = $this->jwt->issue('user-1', ['role' => 'admin']);
        $parts = explode('.', $token);

        // 篡改 payload
        $parts[1] = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(json_encode(['sub' => 'hacker', 'role' => 'evil'])));

        $payload = $this->jwt->decode(implode('.', $parts));
        $this->assertEquals('hacker', $payload['sub']); // decode 不解校验
    }

    /** @test toArray 生成标准 JSON 格式 */
    public function testToArrayFormat(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $arr = $pair->toArray();

        $this->assertArrayHasKey('access_token', $arr);
        $this->assertArrayHasKey('refresh_token', $arr);
        $this->assertArrayHasKey('token_type', $arr);
        $this->assertArrayHasKey('expires_in', $arr);
        $this->assertArrayHasKey('refresh_expires_in', $arr);

        // 可 JSON 序列化
        $json = json_encode($arr);
        $this->assertIsString($json);
        $decoded = json_decode($json, true);
        $this->assertEquals($arr['access_token'], $decoded['access_token']);
    }

    /** @test Builder 运行时覆盖不应污染共享 Jwt 实例 */
    public function testBuilderIssuePairDoesNotPolluteSharedJwt(): void
    {
        // Builder 的 rotation/audience/指纹 覆盖只作用于本次签发
        $this->jwt->builder()
            ->subject('user-1')
            ->rotation(false)
            ->audience('mobile-app')
            ->issuePair();

        // 共享实例（audience = null）不应被写入 builder 的 audience
        $payload = $this->jwt->parse($this->jwt->issue('user-2'));
        $this->assertArrayNotHasKey('aud', $payload);
    }

    /** @test Builder 支持双令牌签发 */
    public function testBuilderIssuePair(): void
    {
        $pair = $this->jwt->builder()
            ->subject('user-1')
            ->claim('role', 'admin')
            ->accessTtl(7200)
            ->refreshTtl(2592000)
            ->issuePair();

        $this->assertInstanceOf(TokenPair::class, $pair);
        $this->assertEquals(7200, $pair->expiresIn);
        $this->assertEquals(2592000, $pair->refreshExpiresIn);

        $payload = $this->jwt->parse($pair->accessToken);
        $this->assertEquals('user-1', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
    }

    /** @test Builder issuePair 缺少 subject 抛异常 */
    public function testBuilderIssuePairThrowsWithoutSubject(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->jwt->builder()->issuePair();
    }

    /** @test Builder asRefreshToken 签发 Refresh Token */
    public function testBuilderAsRefreshToken(): void
    {
        $refreshToken = $this->jwt->builder()
            ->asRefreshToken()
            ->subject('user-1')
            ->ttl(86400 * 30)
            ->issue();

        $payload = $this->jwt->parse($refreshToken);
        $this->assertEquals('refresh', $payload['typ'] ?? '');
    }
}
