<?php
declare(strict_types=1);

namespace wise\jwt\extractor;

use think\Request;

/**
 * Token 提取器接口
 */
interface TokenExtractor
{
    public function extract(Request $request): ?string;
}
