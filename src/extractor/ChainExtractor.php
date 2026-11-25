<?php
declare(strict_types=1);

namespace wise\jwt\extractor;

use think\Request;

/**
 * 责任链提取器
 *
 * 按顺序尝试多个提取器，返回第一个非空结果
 */
class ChainExtractor implements TokenExtractor
{
    /** @var TokenExtractor[] */
    protected array $extractors;

    /**
     * @param TokenExtractor[] $extractors
     */
    public function __construct(array $extractors = [])
    {
        $this->extractors = $extractors;
    }

    public function extract(Request $request): ?string
    {
        foreach ($this->extractors as $extractor) {
            $token = $extractor->extract($request);
            if ($token !== null) {
                return $token;
            }
        }
        return null;
    }
}
