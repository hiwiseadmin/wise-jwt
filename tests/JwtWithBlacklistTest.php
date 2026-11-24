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
        $payload = $this->jwt->parse($token);

        $this->assertTrue($this->jwt->revoke($token));

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
        $token = $this->jwt->issue('user-1', ['role' => 'user'], 60);
        $newToken = $this->jwt->refresh($token);

        $newPayload = $this->jwt->parse($newToken);
        $this->assertEquals('user-1', $newPayload['sub']);
        $this->assertEquals('user', $newPayload['role']);

        $this->expectException(BlacklistedException::class);
        $this->jwt->parse($token);
    }
}
