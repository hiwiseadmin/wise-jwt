<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\Jwt;
use wise\jwt\Builder;
use wise\jwt\signer\HS256Signer;
use wise\jwt\validator\Validator;

class BuilderTest extends TestCase
{
    protected Jwt $jwt;

    protected function setUp(): void
    {
        $this->jwt = new Jwt(
            algorithm: 'HS256',
            signer: new HS256Signer('test-secret-32bytes-long!!'),
            validator: new Validator(0),
            issuer: 'builder-test'
        );
    }

    public function testBuilderFluentInterface(): void
    {
        $token = $this->jwt->builder()
            ->subject(42)
            ->claim('role', 'admin')
            ->claim('tenant', 'acme')
            ->ttl(7200)
            ->audience('mobile')
            ->issue();

        $payload = $this->jwt->parse($token);
        $this->assertEquals('42', $payload['sub']);
        $this->assertEquals('admin', $payload['role']);
        $this->assertEquals('acme', $payload['tenant']);
        $this->assertEquals('mobile', $payload['aud']);
        $this->assertEquals('builder-test', $payload['iss']);
    }

    public function testBuilderMultipleClaims(): void
    {
        $token = $this->jwt->builder()
            ->subject('user-1')
            ->claims(['a' => 1, 'b' => 2])
            ->claim('c', 3)
            ->issue();

        $payload = $this->jwt->parse($token);
        $this->assertEquals(1, $payload['a']);
        $this->assertEquals(2, $payload['b']);
        $this->assertEquals(3, $payload['c']);
    }

    public function testBuilderWithoutSubjectThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->jwt->builder()->issue();
    }

    public function testBuilderCustomIssuer(): void
    {
        $token = $this->jwt->builder()
            ->subject(1)
            ->issuer('custom-iss')
            ->issue();

        $payload = $this->jwt->parse($token);
        $this->assertEquals('custom-iss', $payload['iss']);
    }
}
