<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Payload;

class PayloadTest extends TestCase
{
    public function testToArray(): void
    {
        $payload = new Payload(
            issuer: 'iss',
            subject: '123',
            audience: 'aud',
            issuedAt: 1000,
            notBefore: 1000,
            expiration: 5000,
            jti: 'abc123',
            customClaims: ['role' => 'admin']
        );

        $arr = $payload->toArray();
        $this->assertEquals('iss', $arr['iss']);
        $this->assertEquals('123', $arr['sub']);
        $this->assertEquals('aud', $arr['aud']);
        $this->assertEquals(1000, $arr['iat']);
        $this->assertEquals(5000, $arr['exp']);
        $this->assertEquals('abc123', $arr['jti']);
        $this->assertEquals('admin', $arr['role']);
    }

    public function testFromArray(): void
    {
        $arr = [
            'iss' => 'iss',
            'sub' => '456',
            'aud' => 'app',
            'iat' => 2000,
            'nbf' => 2000,
            'exp' => 6000,
            'jti' => 'xyz',
            'extra_field' => 'value',
        ];

        $payload = Payload::fromArray($arr);
        $this->assertEquals('456', $payload->subject);
        $this->assertEquals(['extra_field' => 'value'], $payload->customClaims);
    }

    public function testFromArrayWithoutOptionalFields(): void
    {
        $arr = ['sub' => '789', 'iat' => 100, 'nbf' => 100, 'exp' => 200, 'jti' => 'j'];
        $payload = Payload::fromArray($arr);
        $this->assertEquals('789', $payload->subject);
        $this->assertNull($payload->audience);
    }
}
