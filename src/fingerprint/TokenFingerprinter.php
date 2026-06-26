<?php
declare(strict_types=1);

namespace wise\jwt\fingerprint;

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
        if ($raw === '' || $raw === '|' || $raw === '||' || $raw === '|||') {
            // 空上下文的指纹应使用随机值防止碰撞
            return hash('sha256', bin2hex(random_bytes(16)));
        }
        return hash('sha256', $raw);
    }

    /**
     * 自动检测当前请求上下文
     */
    protected function detectContext(): array
    {
        return [
            'ua'       => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'lang'     => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            'ip'       => $_SERVER['REMOTE_ADDR'] ?? '',
        ];
    }
}
