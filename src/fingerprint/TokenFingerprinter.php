<?php
declare(strict_types=1);

namespace wise\jwt\fingerprint;

use wise\support\context\ContextualLogger;

/**
 * Token 指纹生成器
 *
 * 签发时绑定设备/IP 指纹，解析时校验。
 * 支持三级安全强度：
 * - LOW：仅 User-Agent
 * - MEDIUM：User-Agent + IP
 * - HIGH：User-Agent + IP + Language + Encoding
 */
class TokenFingerprinter
{
    public const LEVEL_LOW = 'LOW';
    public const LEVEL_MEDIUM = 'MEDIUM';
    public const LEVEL_HIGH = 'HIGH';

    protected string $level;

    /** @var array|null 请求上下文（由中间件/控制器注入） */
    protected ?array $context = null;

    public function __construct(string $level = self::LEVEL_MEDIUM)
    {
        $this->level = $level;
    }

    /**
     * 设置请求上下文
     */
    public function setContext(array $context): self
    {
        $this->context = $context;
        return $this;
    }

    /**
     * 设置安全强度
     */
    public function setLevel(string $level): self
    {
        $this->level = $level;
        return $this;
    }

    /**
     * 从当前请求生成指纹
     *
     * @return string SHA-256 哈希
     */
    public function generate(): string
    {
        return $this->buildFromContext($this->context ?? $this->detectContext());
    }

    /**
     * 从指定上下文生成指纹
     */
    public function generateFrom(array $context): string
    {
        return $this->buildFromContext($context);
    }

    /**
     * 校验指纹是否匹配
     */
    public function verify(string $expectedFingerprint, ?array $context = null): bool
    {
        $actual = $context !== null
            ? $this->buildFromContext($context)
            : $this->generate();

        return hash_equals($expectedFingerprint, $actual);
    }

    /**
     * 获取当前安全强度
     */
    public function getLevel(): string
    {
        return $this->level;
    }

    /**
     * 从上下文构建指纹
     */
    protected function buildFromContext(array $ctx): string
    {
        $parts = [];

        switch ($this->level) {
            case self::LEVEL_HIGH:
                $parts[] = $ctx['ua'] ?? $ctx['user_agent'] ?? '';
                $parts[] = $ctx['lang'] ?? $ctx['accept_language'] ?? '';
                $parts[] = $ctx['encoding'] ?? $ctx['accept_encoding'] ?? '';
                $parts[] = $ctx['ip'] ?? $ctx['remote_addr'] ?? '';
                break;
            case self::LEVEL_MEDIUM:
                $parts[] = $ctx['ua'] ?? $ctx['user_agent'] ?? '';
                $parts[] = $ctx['ip'] ?? $ctx['remote_addr'] ?? '';
                break;
            case self::LEVEL_LOW:
            default:
                $parts[] = $ctx['ua'] ?? $ctx['user_agent'] ?? '';
                break;
        }

        $raw = implode('|', $parts);
        // 空上下文的指纹使用固定空值哈希，确保签发和验证的一致性。
        // 注意：这对空上下文不提供实际保护，应确保业务环境始终有请求上下文。
        if (trim(str_replace('|', '', $raw)) === '') {
            // 显式告警：此时指纹为可预测常量，绑定保护实际失效，
            // 便于宿主（CLI/Swoole 无 request 场景）及时发现配置问题。
            ContextualLogger::warning('[JWT] 指纹生成上下文为空，绑定保护已退化为固定值', ['level' => $this->level]);
            return hash('sha256', 'empty-context-' . $this->level);
        }

        return hash('sha256', $raw);
    }

    /**
     * 自动检测当前请求上下文
     *
     * FPM + Swoole 兼容：优先使用 request()->server()，
     * 回退 $_SERVER（CLI 或未初始化时）。
     */
    protected function detectContext(): array
    {
        $server = self::getServerParams();

        return [
            'ua'       => $server['HTTP_USER_AGENT'] ?? '',
            'lang'     => $server['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'encoding' => $server['HTTP_ACCEPT_ENCODING'] ?? '',
            'ip'       => $server['REMOTE_ADDR'] ?? '',
        ];
    }

    /**
     * 获取 server 参数（FPM + Swoole 兼容）
     */
    private static function getServerParams(): array
    {
        try {
            $request = request();
            if ($request && method_exists($request, 'server')) {
                $server = $request->server();
                if (!empty($server)) {
                    return $server;
                }
            }
        } catch (\Throwable) {
            // request() 不可用
        }

        return $_SERVER;
    }
}
