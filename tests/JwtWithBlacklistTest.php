<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Jwt;
use wise\jwt\signer\HS256Signer;
use wise\jwt\validator\Validator;
use wise\jwt\blacklist\CacheBlacklist;
use wise\jwt\exception\BlacklistedException;

class JwtWithBlacklistTest extends TestCase
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
            issuer: 'test'
        );
    }

    public function testRevokeAndBlock(): void
    {
        $token = $this->jwt->issue('user-1');
        $payload = $this->jwt->parse($token); // 首次通过

        $this->assertTrue($this->jwt->revoke($token));

        // 吊销后解析应该失败
        $this->expectException(BlacklistedException::class);
        $this->jwt->parse($token);
    }

    public function testIsRevoked(): void
    {
        $token = $this->jwt->issue('user-1');
        $payload = $this->jwt->parse($token);
        $jti = $payload['jti'];

        $this->assertFalse($this->jwt->isRevoked($jti));

        $this->jwt->revoke($token);
        $this->assertTrue($this->jwt->isRevoked($jti));
    }

    public function testRefreshWithBlacklist(): void
    {
        $token = $this->jwt->issue('user-1', ['role' => 'user']);
        $newToken = $this->jwt->refresh($token);

        // 新 token 可解析
        $newPayload = $this->jwt->parse($newToken);
        $this->assertEquals('user-1', $newPayload['sub']);
        $this->assertEquals('user', $newPayload['role']);

        // 旧 token 已被吊销
        $this->expectException(BlacklistedException::class);
        $this->jwt->parse($token);
    }
}
