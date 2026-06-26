<?php
declare(strict_types=1);

namespace wise\jwt\tests;

use PHPUnit\Framework\TestCase;
use think\Request;
use wise\jwt\extractor\BearerHeaderExtractor;
use wise\jwt\extractor\CookieExtractor;
use wise\jwt\extractor\QueryExtractor;
use wise\jwt\extractor\ChainExtractor;

/**
 * Token 提取器链测试
 */
class TokenExtractorTest extends TestCase
{
    // ── BearerHeaderExtractor ──

    /** @test */
    public function bearerExtractsToken(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = Request::create('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer abc.def.ghi',
        ]);

        $token = $extractor->extract($request);
        $this->assertEquals('abc.def.ghi', $token);
    }

    /** @test */
    public function bearerNoAuthHeaderReturnsNull(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = Request::create('/api/user');

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function bearerNonBearerPrefixReturnsNull(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = Request::create('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Basic xxx',
        ]);

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function bearerWithLowerCasePrefix(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = Request::create('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'bearer abc.def.ghi',
        ]);

        $token = $extractor->extract($request);
        $this->assertEquals('abc.def.ghi', $token);
    }

    /** @test */
    public function bearerCustomHeaderName(): void
    {
        $extractor = new BearerHeaderExtractor('X-Auth-Token');
        $request = Request::create('/api/user', 'GET', [], [], [], [
            'HTTP_X_AUTH_TOKEN' => 'Bearer custom.token.here',
        ]);

        $this->assertEquals('custom.token.here', $extractor->extract($request));
    }

    // ── CookieExtractor ──

    /** @test */
    public function cookieExtractsToken(): void
    {
        $extractor = new CookieExtractor('wise_token');
        $request = Request::create('/api/user', 'GET', [], ['wise_token' => 'abc.def.ghi']);

        $this->assertEquals('abc.def.ghi', $extractor->extract($request));
    }

    /** @test */
    public function cookieNotFoundReturnsNull(): void
    {
        $extractor = new CookieExtractor('wise_token');
        $request = Request::create('/api/user');

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function cookieCustomName(): void
    {
        $extractor = new CookieExtractor('my_token');
        $request = Request::create('/api/user', 'GET', [], ['my_token' => 'xyz.token']);

        $this->assertEquals('xyz.token', $extractor->extract($request));
    }

    // ── QueryExtractor ──

    /** @test */
    public function queryExtractsToken(): void
    {
        $extractor = new QueryExtractor('token');
        $request = Request::create('/api/user?token=abc.def.ghi');

        $this->assertEquals('abc.def.ghi', $extractor->extract($request));
    }

    /** @test */
    public function queryNotFoundReturnsNull(): void
    {
        $extractor = new QueryExtractor('token');
        $request = Request::create('/api/user');

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function queryCustomParamName(): void
    {
        $extractor = new QueryExtractor('access_token');
        $request = Request::create('/api/user?access_token=my.token');

        $this->assertEquals('my.token', $extractor->extract($request));
    }

    // ── ChainExtractor ──

    /** @test */
    public function chainReturnsFirstNonEmpty(): void
    {
        $chain = new ChainExtractor([
            new BearerHeaderExtractor('Authorization'),
            new QueryExtractor('token'),
        ]);

        $request = Request::create('/api/user?token=query.token', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer bearer.token',
        ]);

        // Bearer 应该优先
        $this->assertEquals('bearer.token', $chain->extract($request));
    }

    /** @test */
    public function chainFallsBackToNext(): void
    {
        $chain = new ChainExtractor([
            new BearerHeaderExtractor('Authorization'),
            new QueryExtractor('token'),
        ]);

        // 只有 query 有 token
        $request = Request::create('/api/user?token=fallback.token');

        $this->assertEquals('fallback.token', $chain->extract($request));
    }

    /** @test */
    public function chainAllEmptyReturnsNull(): void
    {
        $chain = new ChainExtractor([
            new BearerHeaderExtractor('Authorization'),
            new CookieExtractor('wise_token'),
            new QueryExtractor('token'),
        ]);

        $request = Request::create('/api/user');
        $this->assertNull($chain->extract($request));
    }

    /** @test */
    public function chainCookiePriorityOverQuery(): void
    {
        $chain = new ChainExtractor([
            new CookieExtractor('wise_token'),
            new QueryExtractor('token'),
        ]);

        $request = Request::create('/api/user?token=query.token', 'GET', [], ['wise_token' => 'cookie.token']);

        $this->assertEquals('cookie.token', $chain->extract($request));
    }

    /** @test */
    public function chainEmptyExtractorsReturnsNull(): void
    {
        $chain = new ChainExtractor([]);
        $request = Request::create('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer token',
        ]);

        $this->assertNull($chain->extract($request));
    }
}
