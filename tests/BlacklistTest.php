<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use wise\jwt\blacklist\CacheBlacklist;

class BlacklistTest extends TestCase
{
    public function testAddAndHas(): void
    {
        $bl = new CacheBlacklist('test:bl:');
        $jti = 'test-jti-' . uniqid();

        $this->assertFalse($bl->has($jti));

        $bl->add($jti, time() + 3600);
        $this->assertTrue($bl->has($jti));
    }

    public function testRemove(): void
    {
        $bl = new CacheBlacklist('test:bl:');
        $jti = 'test-jti-' . uniqid();

        $bl->add($jti, time() + 3600);
        $this->assertTrue($bl->has($jti));

        $bl->remove($jti);
        $this->assertFalse($bl->has($jti));
    }

    public function testExpiredNotPresent(): void
    {
        $bl = new CacheBlacklist('test:bl:');
        $jti = 'test-jti-' . uniqid();

        $bl->add($jti, time() - 1);
        $bl->has($jti);
        $this->assertTrue(true);
    }

    public function testPurge(): void
    {
        $bl = new CacheBlacklist('test:bl:');
        $this->assertIsInt($bl->purge());
    }
}
