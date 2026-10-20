<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\TokenPair;

class TokenPairTest extends TestCase
{
    public function testCreateTokenPair(): void
    {
        $pair = new TokenPair(
            accessToken: 'eyJhbGciOi...',
            refreshToken: 'eyJhbGciOi...',
            tokenType: 'Bearer',
            expiresIn: 7200,
            refreshExpiresIn: 2592000
        );

        $this->assertEquals('eyJhbGciOi...', $pair->accessToken);
        $this->assertEquals('eyJhbGciOi...', $pair->refreshToken);
        $this->assertEquals('Bearer', $pair->tokenType);
        $this->assertEquals(7200, $pair->expiresIn);
        $this->assertEquals(2592000, $pair->refreshExpiresIn);
    }

    public function testToArray(): void
    {
        $pair = new TokenPair(
            accessToken: 'at-token',
            refreshToken: 'rt-token',
            tokenType: 'Bearer',
            expiresIn: 3600,
            refreshExpiresIn: 86400
        );

        $arr = $pair->toArray();

        $this->assertIsArray($arr);
        $this->assertArrayHasKey('access_token', $arr);
        $this->assertArrayHasKey('refresh_token', $arr);
        $this->assertArrayHasKey('token_type', $arr);
        $this->assertArrayHasKey('expires_in', $arr);
        $this->assertArrayHasKey('refresh_expires_in', $arr);

        $this->assertEquals('at-token', $arr['access_token']);
        $this->assertEquals('rt-token', $arr['refresh_token']);
        $this->assertEquals('Bearer', $arr['token_type']);
        $this->assertEquals(3600, $arr['expires_in']);
        $this->assertEquals(86400, $arr['refresh_expires_in']);
    }

    public function testReadonlyProperties(): void
    {
        $pair = new TokenPair('a', 'b');
        $this->assertIsString($pair->accessToken);
        $this->assertIsString($pair->refreshToken);
    }

    public function testDefaultValues(): void
    {
        $pair = new TokenPair('at', 'rt');
        $this->assertEquals('Bearer', $pair->tokenType);
        $this->assertEquals(7200, $pair->expiresIn);
        $this->assertEquals(2592000, $pair->refreshExpiresIn);
    }
}
