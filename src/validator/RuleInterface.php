<?php
declare(strict_types=1);

namespace wise\jwt\validator;

/**
 * 声明校验规则接口
 */
interface RuleInterface
{
    /**
     * @throws \wise\jwt\exception\JwtException 校验失败时抛出
     */
    public function validate(array $payload): void;
}
