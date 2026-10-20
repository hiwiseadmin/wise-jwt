<?php
declare(strict_types=1);

namespace wise\jwt\validator;

use wise\jwt\exception\JwtException;

/**
 * 接收者校验规则
 */
class AudienceRule implements RuleInterface
{
    public function __construct(private string $expectedAudience) {}

    public function validate(array $payload): void
    {
        // fail-closed：既然启用了 audience 校验，缺失 aud 的令牌一律拒绝，
        // 与 ExpirationRule（缺 exp 视为过期）、Jwt::checkVersion()（缺 ver 视为失效）
        // 的基线保持一致，否则无 aud 的令牌会绕过受众隔离。
        $aud = $payload['aud'] ?? null;
        if ($aud === null || $aud === '') {
            throw new JwtException('令牌缺少接收者声明');
        }

        // 支持单个或数组
        $audList = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->expectedAudience, $audList, true)) {
            throw new JwtException('接收者验证失败');
        }
    }
}
