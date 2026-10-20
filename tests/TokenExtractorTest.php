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
    /**
     * 构造 think\Request 测试实例
     *
     * think\Request 没有 Laravel 风格的静态 `create()`（本包测试此前误用），
     * 这里用 TP 原生的 withGet / withCookie / withHeader / withServer 构造等价请求。
     * 参数顺序刻意与 Laravel 风格的静态 create() 保持一致，便于调用点直接替换。
     *
     * @param string               $uri     形如 '/api/user?token=abc'
     * @param string               $method  请求方法（提取器不依赖，仅为对齐签名保留）
     * @param array<string, mixed> $get     额外查询参数
     * @param array<string, mixed> $cookies Cookie
     * @param array<string, mixed> $files   上传文件（未使用，仅为对齐签名保留）
     * @param array<string, mixed> $server  形如 ['HTTP_AUTHORIZATION' => 'Bearer x']
     */
    private function makeRequest(
        string $uri = '/api/user',
        string $method = 'GET',
        array $get = [],
        array $cookies = [],
        array $files = [],
        array $server = []
    ): Request {
        $query = $get;
        $question = strpos($uri, '?');
        if ($question !== false) {
            parse_str(substr($uri, $question + 1), $parsed);
            $query = array_merge($query, $parsed);
        }

        // HTTP_X_AUTH_TOKEN → X-AUTH-TOKEN：
        // Request::header() 查询时会转小写并把 '_' 换成 '-'，故此处先生成 '-' 形态
        $header = [];
        foreach ($server as $key => $value) {
            if (stripos((string) $key, 'HTTP_') === 0) {
                $header[str_replace('_', '-', substr((string) $key, 5))] = $value;
            }
        }

        return (new Request())
            ->withGet($query)
            ->withCookie($cookies)
            ->withHeader($header)
            ->withServer($server);
    }

    // ── BearerHeaderExtractor ──

    /** @test */
    public function bearerExtractsToken(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = $this->makeRequest('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer abc.def.ghi',
        ]);

        $token = $extractor->extract($request);
        $this->assertEquals('abc.def.ghi', $token);
    }

    /** @test */
    public function bearerNoAuthHeaderReturnsNull(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = $this->makeRequest('/api/user');

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function bearerNonBearerPrefixReturnsNull(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = $this->makeRequest('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Basic xxx',
        ]);

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function bearerWithLowerCasePrefix(): void
    {
        $extractor = new BearerHeaderExtractor('Authorization');
        $request = $this->makeRequest('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'bearer abc.def.ghi',
        ]);

        $token = $extractor->extract($request);
        $this->assertEquals('abc.def.ghi', $token);
    }

    /** @test */
    public function bearerCustomHeaderName(): void
    {
        $extractor = new BearerHeaderExtractor('X-Auth-Token');
        $request = $this->makeRequest('/api/user', 'GET', [], [], [], [
            'HTTP_X_AUTH_TOKEN' => 'Bearer custom.token.here',
        ]);

        $this->assertEquals('custom.token.here', $extractor->extract($request));
    }

    // ── CookieExtractor ──

    /** @test */
    public function cookieExtractsToken(): void
    {
        $extractor = new CookieExtractor('wise_token');
        $request = $this->makeRequest('/api/user', 'GET', [], ['wise_token' => 'abc.def.ghi']);

        $this->assertEquals('abc.def.ghi', $extractor->extract($request));
    }

    /** @test */
    public function cookieNotFoundReturnsNull(): void
    {
        $extractor = new CookieExtractor('wise_token');
        $request = $this->makeRequest('/api/user');

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function cookieCustomName(): void
    {
        $extractor = new CookieExtractor('my_token');
        $request = $this->makeRequest('/api/user', 'GET', [], ['my_token' => 'xyz.token']);

        $this->assertEquals('xyz.token', $extractor->extract($request));
    }

    // ── QueryExtractor ──

    /** @test */
    public function queryExtractsToken(): void
    {
        $extractor = new QueryExtractor('token');
        $request = $this->makeRequest('/api/user?token=abc.def.ghi');

        $this->assertEquals('abc.def.ghi', $extractor->extract($request));
    }

    /** @test */
    public function queryNotFoundReturnsNull(): void
    {
        $extractor = new QueryExtractor('token');
        $request = $this->makeRequest('/api/user');

        $this->assertNull($extractor->extract($request));
    }

    /** @test */
    public function queryCustomParamName(): void
    {
        $extractor = new QueryExtractor('access_token');
        $request = $this->makeRequest('/api/user?access_token=my.token');

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

        $request = $this->makeRequest('/api/user?token=query.token', 'GET', [], [], [], [
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
        $request = $this->makeRequest('/api/user?token=fallback.token');

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

        $request = $this->makeRequest('/api/user');
        $this->assertNull($chain->extract($request));
    }

    /** @test */
    public function chainCookiePriorityOverQuery(): void
    {
        $chain = new ChainExtractor([
            new CookieExtractor('wise_token'),
            new QueryExtractor('token'),
        ]);

        $request = $this->makeRequest('/api/user?token=query.token', 'GET', [], ['wise_token' => 'cookie.token']);

        $this->assertEquals('cookie.token', $chain->extract($request));
    }

    /** @test */
    public function chainEmptyExtractorsReturnsNull(): void
    {
        $chain = new ChainExtractor([]);
        $request = $this->makeRequest('/api/user', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer token',
        ]);

        $this->assertNull($chain->extract($request));
    }
}
