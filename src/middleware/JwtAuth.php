<?php
declare(strict_types=1);

namespace wise\jwt\middleware;

use think\Request;
use think\Response;
use think\facade\Log;
use wise\jwt\JwtGuardManager;
use wise\jwt\throttle\RateLimiter;
use wise\jwt\throttle\ThrottleException;
use wise\jwt\extractor\ChainExtractor;
use wise\jwt\extractor\BearerHeaderExtractor;
use wise\jwt\extractor\CookieExtractor;
use wise\jwt\extractor\QueryExtractor;
use wise\jwt\extractor\TokenExtractor;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\TokenExpiredException;

/**
 * JWT 鉴权中间件
 *
 * P1 增强：集成频率限制（Rate Limiting）
 *
 * 支持多 Guard，通过构造参数指定：
 * Route::get('/api/admin')->middleware('jwt.auth:admin');
 */
class JwtAuth
{
    protected JwtGuardManager $guardManager;
    protected array $config;
    protected ?TokenExtractor $extractor = null;
    protected ?string $guard = null;

    /** P1：频率限制器 */
    protected ?RateLimiter $rateLimiter = null;

    public function __construct(JwtGuardManager $guardManager, array $config = [], ?string $guard = null)
    {
        $this->guardManager = $guardManager;
        $this->config = $config;
        $this->guard = $guard;

        // ── P1: 初始化频率限制器 ──
        $throttle = $config['throttle'] ?? [];
        if ($throttle['enable'] ?? false) {
            $this->rateLimiter = new RateLimiter(
                (int) ($throttle['max_attempts'] ?? 5),
                (int) ($throttle['decay_seconds'] ?? 60),
                $throttle['prefix'] ?? 'jwt:throttle:'
            );
        }
    }

    public function handle(Request $request, \Closure $next): Response
    {
        $jwt = $this->guardManager->guard($this->guard);

        // ── P1: 频率限制检查 ──
        if ($this->rateLimiter !== null) {
            $throttleKey = $this->buildThrottleKey($request);
            if ($this->rateLimiter->tooManyAttempts($throttleKey)) {
                $cooldown = $this->rateLimiter->cooldown($throttleKey);
                Log::warning('[JWT] 频率限制触发', ['key' => $throttleKey, 'cooldown' => $cooldown]);
                return $this->tooManyRequests($cooldown);
            }
        }

        $token = $this->getExtractor()->extract($request);

        if (!$token) {
            // P1: 记录失败（无令牌）
            $this->recordFailure($request);
            return $this->unauthorized('缺少认证令牌');
        }

        try {
            $payload = $jwt->parse($token);
        } catch (TokenExpiredException $e) {
            $this->recordFailure($request);
            return $this->unauthorized('令牌已过期');
        } catch (JwtException $e) {
            $this->recordFailure($request);
            return $this->unauthorized($e->getMessage());
        }

        // 鉴权成功 — 重置失败计数
        $this->clearFailure($request);

        // 注入到 request
        $request->jwt_payload = $payload;
        $request->jwt_token = $token;

        $response = $next($request);

        // 自动续签
        if (($this->config['auto_refresh'] ?? true) && $jwt->shouldRefresh($payload)) {
            try {
                $newToken = $jwt->refresh($token);
                $response->header('X-New-Token', $newToken);
            } catch (\Throwable) {
                // 续签失败不影响响应
            }
        }

        return $response;
    }

    /**
     * 构建限流键（默认按 IP）
     */
    protected function buildThrottleKey(Request $request): string
    {
        $throttle = $this->config['throttle'] ?? [];
        $keyType = $throttle['key_type'] ?? 'ip';

        return match ($keyType) {
            'ip'     => $request->ip(),
            'route'  => $request->baseUrl(),
            'ip_route' => $request->ip() . ':' . $request->baseUrl(),
            default  => $request->ip(),
        };
    }

    /**
     * 记录失败尝试
     */
    protected function recordFailure(Request $request): void
    {
        if ($this->rateLimiter !== null) {
            $this->rateLimiter->hit($this->buildThrottleKey($request));
        }
    }

    /**
     * 清除失败计数（鉴权成功后）
     */
    protected function clearFailure(Request $request): void
    {
        if ($this->rateLimiter !== null) {
            $this->rateLimiter->clear($this->buildThrottleKey($request));
        }
    }

    protected function getExtractor(): TokenExtractor
    {
        if ($this->extractor !== null) {
            return $this->extractor;
        }

        $extractors = [];
        $names = $this->config['token']['extractors'] ?? ['bearer', 'cookie', 'query'];

        foreach ($names as $name) {
            switch ($name) {
                case 'bearer':
                    $extractors[] = new BearerHeaderExtractor(
                        $this->config['token']['header_name'] ?? 'Authorization'
                    );
                    break;
                case 'cookie':
                    $extractors[] = new CookieExtractor(
                        $this->config['token']['cookie_name'] ?? 'wise_token'
                    );
                    break;
                case 'query':
                    $extractors[] = new QueryExtractor(
                        $this->config['token']['query_name'] ?? 'token'
                    );
                    break;
            }
        }

        return $this->extractor = new ChainExtractor($extractors);
    }

    protected function unauthorized(string $message): Response
    {
        return json([
            'code' => 401,
            'msg'  => $message,
            'data' => null,
        ], 401);
    }

    /**
     * P1: 频率超限响应
     */
    protected function tooManyRequests(int $retryAfter): Response
    {
        return json([
            'code' => 429,
            'msg'  => '请求过于频繁，请 ' . $retryAfter . ' 秒后再试',
            'data' => ['retry_after' => $retryAfter],
        ], 429)->header(['Retry-After' => (string) $retryAfter]);
    }
}
