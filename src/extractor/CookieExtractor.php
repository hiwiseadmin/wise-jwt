<?php
declare(strict_types=1);

namespace wise\jwt\extractor;

use think\Request;

/**
 * Cookie 提取器
 *
 * 从指定 Cookie 中提取 token
 */
class CookieExtractor implements TokenExtractor
{
    public function __construct(protected string $cookieName = 'wise_token') {}

    public function extract(Request $request): ?string
    {
        $cookie = $request->cookie($this->cookieName, '');
        return $cookie !== '' ? $cookie : null;
    }
}
