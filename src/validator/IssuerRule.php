<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 签发者校验规则
 */
class IssuerRule implements RuleInterface
{
    public function __construct(private string $expectedIssuer) {}

    public function validate(array $payload): void
    {
        if (($payload['iss'] ?? '') !== $this->expectedIssuer) {
            throw new JwtException('签发者验证失败');
        }
    }
}
