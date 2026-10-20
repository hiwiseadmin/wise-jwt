<?php
declare(strict_types=1);

namespace wise\jwt\extractor;

use think\Request;

/**
 * Bearer Header 提取器
 *
 * 从 Authorization: Bearer <token> 中提取 token
 */
class BearerHeaderExtractor implements TokenExtractor
{
    public function __construct(protected string $headerName = 'Authorization') {}

    public function extract(Request $request): ?string
    {
        $header = (string) $request->header($this->headerName, '');
        if ($header !== '' && stripos($header, 'Bearer ') === 0) {
            return trim(substr($header, 7));
        }
        return null;
    }
}
