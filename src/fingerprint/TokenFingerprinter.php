<?php
declare(strict_types=1);

namespace wise\jwt\fingerprint;

use wise\support\context\ContextualLogger;
use wise\support\context\RequestContext;

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

    /**
     * 请求上下文（由中间件/控制器注入）
     *
     * ⚠️ 本实例是 worker 级共享对象（JwtGuardManager → Jwt → 本类），
     * 直接只存实例属性会让常驻进程把上一个请求的 UA/IP 带进下一个请求。
     * 因此同时写入 RequestContext（按协程/请求隔离），读取时优先取请求级数据。
     *
     * @var array|null
     */
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

        if (class_exists(RequestContext::class)) {
            RequestContext::set('jwt_fingerprint_context', $context);
        }

        return $this;
    }

    /**
     * 读取当前请求上下文
     *
     * 优先请求级容器（协程隔离），缺失时回退实例属性（CLI / 单测场景）。
     */
    protected function context(): array
    {
        if (class_exists(RequestContext::class)) {
            $scoped = RequestContext::get('jwt_fingerprint_context');
            if (is_array($scoped)) {
                return $scoped;
            }
        }

        return $this->context ?? [];
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
        return $this->buildFromContext($this->context() ?: $this->detectContext());
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
        if (trim(str_replace('|', '', $raw)) === '') {
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
        }

        return [];
    }
}
