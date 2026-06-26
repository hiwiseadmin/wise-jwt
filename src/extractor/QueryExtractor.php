<?php
declare(strict_types=1);

namespace wise\jwt\extractor;

use think\Request;

/**
 * Query 参数提取器
 *
 * 从 URL Query 参数中提取 token
 */
class QueryExtractor implements TokenExtractor
{
    public function __construct(protected string $queryName = 'token') {}

    public function extract(Request $request): ?string
    {
        $token = $request->get($this->queryName, '');
        return $token !== '' ? $token : null;
    }
}
