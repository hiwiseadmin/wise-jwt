<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Jwt;
use wise\jwt\TokenPair;
use wise\jwt\signer\HS256Signer;
use wise\jwt\validator\Validator;
use wise\jwt\blacklist\CacheBlacklist;
use wise\jwt\exception\BlacklistedException;
use wise\jwt\exception\TokenInvalidException;

/**
 * Refresh Token Rotation 安全测试
 *
 * 覆盖：
 * - 反重放攻击（多次使用同一 Refresh Token）
 * - 长链轮换下的黑名单一致性
 * - Rotation 禁用时的行为
 * - jti 精确追踪
 * - 吊销后不可刷新
 * - 多层刷新后旧令牌全部失效
 */
class RefreshTokenRotationSecurityTest extends TestCase
{
    protected Jwt $jwt;
    protected CacheBlacklist $blacklist;

    protected function setUp(): void
    {
        $this->blacklist = new CacheBlacklist('test:rotation:');
        $this->jwt = new Jwt(
            algorithm: 'HS256',
            signer: new HS256Signer('test-rotation-secret-32bytes!!!'),
            validator: new Validator(0),
            blacklist: $this->blacklist,
            issuer: 'test-rotation',
            ttl: 3600,
            refreshTtl: 1800,
            audience: null,
            refreshTokenTtl: 86400,
            refreshTokenRotation: true,
            refreshTokenFingerprint: false
        );
    }

    protected function tearDown(): void
    {
        $this->blacklist->purge();
    }


    public function testReplayAttackDetected(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $this->jwt->refreshAccessToken($pair->refreshToken);

        $this->expectException(BlacklistedException::class);
        $this->jwt->refreshAccessToken($pair->refreshToken);
    }

    public function testTripleUseOfSameRefreshToken(): void
    {
        $pair = $this->jwt->issuePair('user-1');

        $pair2 = $this->jwt->refreshAccessToken($pair->refreshToken);
        $this->assertNotNull($pair2);

        try {
            $this->jwt->refreshAccessToken($pair->refreshToken);
            $this->fail('应抛出 BlacklistedException');
        } catch (BlacklistedException $e) {
            $this->assertTrue(true);
        }

        try {
            $this->jwt->refreshAccessToken($pair->refreshToken);
            $this->fail('应抛出 BlacklistedException');
        } catch (BlacklistedException $e) {
            $this->assertTrue(true);
        }

        $pair3 = $this->jwt->refreshAccessToken($pair2->refreshToken);
        $this->assertInstanceOf(TokenPair::class, $pair3);
    }

    public function testRapidSuccessiveRefreshEachSucceeds(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $chain = [$pair];

        for ($i = 0; $i < 5; $i++) {
            $last = end($chain);
            $newPair = $this->jwt->refreshAccessToken($last->refreshToken);
            $chain[] = $newPair;

            $payload = $this->jwt->parse($newPair->accessToken);
            $this->assertEquals('user-1', $payload['sub']);
        }

        $this->assertCount(6, $chain);
    }


    public function testAllOldTokensBlacklistedAfterChain(): void
    {
        $pairs = [$this->jwt->issuePair('user-1')];
        $oldRefreshTokens = [];

        for ($i = 0; $i < 3; $i++) {
            $last = end($pairs);
            $oldRefreshTokens[] = $last->refreshToken;
            $pairs[] = $this->jwt->refreshAccessToken($last->refreshToken);
        }

        foreach ($oldRefreshTokens as $rt) {
            try {
                $this->jwt->refreshAccessToken($rt);
                $this->fail('旧 Refresh Token 应触发 BlacklistedException');
            } catch (BlacklistedException $e) {
                $this->assertTrue(true);
            }
        }

        $lastPair = end($pairs);
        $newPair = $this->jwt->refreshAccessToken($lastPair->refreshToken);
        $this->assertInstanceOf(TokenPair::class, $newPair);
    }

    public function testOldAccessTokenStillValidAfterRotation(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $this->jwt->refreshAccessToken($pair->refreshToken);

        $payload = $this->jwt->parse($pair->accessToken);
        $this->assertEquals('user-1', $payload['sub']);
    }

    public function testJtiTrackedCorrectlyAfterRotation(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $rtPayload = $this->jwt->parse($pair->refreshToken);
        $oldJti = $rtPayload['jti'] ?? '';

        $this->jwt->refreshAccessToken($pair->refreshToken);

        $this->assertTrue($this->jwt->isRevoked($oldJti));

        $newPair = $this->jwt->issuePair('user-2');
        $newPayload = $this->jwt->parse($newPair->refreshToken);
        $this->assertFalse($this->jwt->isRevoked($newPayload['jti'] ?? ''));
    }


    public function testRotationDisabled_TokenNotRevoked(): void
    {
        $jwtNoRotation = new Jwt(
            algorithm: 'HS256',
            signer: new HS256Signer('no-rotation-secret-32bytes!!!'),
            validator: new Validator(0),
            blacklist: $this->blacklist,
            issuer: 'test',
            ttl: 3600,
            refreshTokenTtl: 86400,
            refreshTokenRotation: false,
        );

        $pair = $jwtNoRotation->issuePair('user-1');
        $rtPayload = $jwtNoRotation->parse($pair->refreshToken);
        $oldJti = $rtPayload['jti'] ?? '';

        $newPair = $jwtNoRotation->refreshAccessToken($pair->refreshToken);

        $this->assertFalse($jwtNoRotation->isRevoked($oldJti));
        $this->assertNotNull($newPair);
    }

    public function testRotationDisabled_TokenReusable(): void
    {
        $jwtNoRotation = new Jwt(
            algorithm: 'HS256',
            signer: new HS256Signer('reuse-secret-key-32bytes!!!!'),
            validator: new Validator(0),
            blacklist: $this->blacklist,
            issuer: 'test',
            ttl: 3600,
            refreshTokenTtl: 86400,
            refreshTokenRotation: false,
        );

        $pair = $jwtNoRotation->issuePair('user-1');
        $pair2 = $jwtNoRotation->refreshAccessToken($pair->refreshToken);
        $this->assertNotNull($pair2);

        $pair3 = $jwtNoRotation->refreshAccessToken($pair->refreshToken);
        $this->assertNotNull($pair3);
    }


    public function testRevokedTokenCannotRefresh(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $this->assertTrue($this->jwt->revokeRefreshToken($pair->refreshToken));

        $this->expectException(BlacklistedException::class);
        $this->jwt->refreshAccessToken($pair->refreshToken);
    }

    public function testRevokedTokenJtiInBlacklist(): void
    {
        $pair = $this->jwt->issuePair('user-1');
        $rtPayload = $this->jwt->parse($pair->refreshToken);
        $jti = $rtPayload['jti'] ?? '';

        $this->jwt->revokeRefreshToken($pair->refreshToken);
        $this->assertTrue($this->jwt->isRevoked($jti));
    }

    public function testAccessTokenRejectedAsRefreshToken(): void
    {
        $pair = $this->jwt->issuePair('user-1');

        $this->expectException(TokenInvalidException::class);
        $this->expectExceptionMessage('非法的令牌类型');
        $this->jwt->refreshAccessToken($pair->accessToken);
    }


    public function testCustomClaimsSurviveRefreshChain(): void
    {
        $pair = $this->jwt->issuePair('user-1', ['role' => 'admin', 'tenant' => 'acme']);
        $chain = [$pair];

        for ($i = 0; $i < 3; $i++) {
            $last = end($chain);
            $chain[] = $this->jwt->refreshAccessToken($last->refreshToken);
        }

        $lastPair = end($chain);
        $payload = $this->jwt->parse($lastPair->accessToken);
        $this->assertEquals('user-1', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
        $this->assertEquals('acme', $payload['tenant']);
    }

    public function testRotationWorksWithoutBlacklist(): void
    {
        $jwtNoBlacklist = new Jwt(
            algorithm: 'HS256',
            signer: new HS256Signer('no-bl-secret-key-32bytes!!!!'),
            validator: new Validator(0),
            blacklist: null,
            issuer: 'test',
            ttl: 3600,
            refreshTokenTtl: 86400,
            refreshTokenRotation: true,
        );

        $pair = $jwtNoBlacklist->issuePair('user-1');
        $newPair = $jwtNoBlacklist->refreshAccessToken($pair->refreshToken);
        $this->assertInstanceOf(TokenPair::class, $newPair);
        $this->assertNotNull($newPair);
    }

    public function testRevokeManyTracksAllJtis(): void
    {
        $tokens = [];
        $jtis = [];

        for ($i = 0; $i < 3; $i++) {
            $token = $this->jwt->issue("user-{$i}");
            $payload = $this->jwt->parse($token);
            $tokens[] = $token;
            $jtis[] = $payload['jti'];
        }

        $count = $this->jwt->revokeMany($tokens);
        $this->assertEquals(3, $count);

        foreach ($jtis as $jti) {
            $this->assertTrue($this->jwt->isRevoked($jti));
        }
    }

    public function testMalformedTokenInRefreshAccessToken(): void
    {
        $this->expectException(TokenInvalidException::class);
        $this->jwt->refreshAccessToken('not.a.valid.jwt');
    }
}
