<?php
declare(strict_types=1);

namespace wise\jwt\middleware;

use think\Request;
use think\Response;
use wise\support\context\ContextualLogger;
use wise\jwt\JwtGuardManager;
use wise\jwt\throttle\RateLimiter;
use wise\jwt\throttle\ThrottleException;
use wise\jwt\extractor\ChainExtractor;
use wise\jwt\extractor\BearerHeaderExtractor;
use wise\jwt\extractor\CookieExtractor;
use wise\jwt\extractor\QueryExtractor;
use wise\jwt\extractor\TokenExtractor;
use wise\jwt\exception\ErrorCode;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\TokenExpiredException;
use wise\support\context\RequestContext;

/**
 * JWT 鉴权中间件
 *
 * P1 增强：集成频率限制（Rate Limiting）
 * P2 增强：路由级 Guard 切换 + 提取器自定义
 * P3 增强：可注入「错误响应器」与「认证成功钩子」，供宿主应用对齐自身响应协议
 *
 * 路由级配置（TP8 会把参数以「变参」形式透传给 handle()，因此必须用变参而非数组）：
 * Route::get('/api/admin')->middleware(JwtAuth::class, 'admin');                 // 指定 Guard
 * Route::get('/api/admin')->middleware(JwtAuth::class, 'admin', 'bearer');       // Guard + 仅 Bearer 提取
 * Route::get('/api/dl')   ->middleware(JwtAuth::class, 'app', 'bearer', 'query'); // 指定 Guard + 多提取器
 * Route::group('api', fn () => ...)->middleware([[JwtAuth::class, ['app', 'bearer']]]); // 分组嵌套数组写法
 *
 * 钩子用法（宿主导入，引擎逻辑保持单份）：
 * <pre>
 * $auth = app(\wise\jwt\middleware\JwtAuth::class);
 * $auth->setErrorResponder(function (\think\Request $request, array $ctx): \think\Response {
 *     // $ctx = ['code' => int, 'message' => string,
 *     //         'exception' => ?\Throwable, 'retry_after' => ?int]
 *     // code 为 wise\jwt\exception\ErrorCode 值（50000~50100），宿主据此映射自身协议码
 *     return json([...]); // 自定义错误信封
 * });
 * $auth->setAuthenticatedHook(function (\think\Request $request, array $payload, string $token): void {
 *     // 认证通过、上下文注入后、进入业务前回调
 * });
 * </pre>
 */
class JwtAuth
{
    protected JwtGuardManager $guardManager;
    protected array $config;

    /**
     * 提取器链缓存，按「提取器名组合」为键。
     *
     * 改为按入参缓存而非单一实例属性，避免常驻运行时把上一次请求的
     * 路由级提取器配置带到下一次请求。
     *
     * @var array<string, TokenExtractor>
     */
    protected array $extractors = [];

    protected ?string $guard = null;

    /** P1：频率限制器 */
    protected ?RateLimiter $rateLimiter = null;

    /**
     * P3：自定义错误响应器。
     *
     * 签名：fn(Request $request, array $ctx): ?\think\Response
     * 返回 Response 时使用该响应；返回 null 时回退内置裸格式。
     *
     * @var callable|null
     */
    protected $errorResponder = null;

    /**
     * P3：认证成功钩子（payload 校验通过并注入上下文后、进入业务前回调）。
     *
     * 签名：fn(Request $request, array $payload, string $token): void
     *
     * @var callable|null
     */
    protected $authenticatedHook = null;

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

    /**
     * 注入自定义错误响应器。
     *
     * @param callable|null $responder fn(Request, array $ctx): ?\think\Response
     * @return $this
     */
    public function setErrorResponder(?callable $responder): self
    {
        $this->errorResponder = $responder;
        return $this;
    }

    /**
     * 注入认证成功钩子。
     *
     * @param callable|null $hook fn(Request, array $payload, string $token): void
     * @return $this
     */
    public function setAuthenticatedHook(?callable $hook): self
    {
        $this->authenticatedHook = $hook;
        return $this;
    }

    public function handle(Request $request, \Closure $next, ?string $guard = null, string ...$extractorNames): Response
    {
        // 路由级 Guard 覆盖：使用局部变量而非写回实例属性，
        // 避免 Swoole/Workerman 等常驻运行时中间件实例复用导致的 Guard 串档。
        $activeGuard = $guard ?? $this->guard;

        $jwt = $this->guardManager->guard($activeGuard);

        // ── P1: 频率限制检查 ──
        if ($this->rateLimiter !== null) {
            $throttleKey = $this->buildThrottleKey($request);
            if ($this->rateLimiter->tooManyAttempts($throttleKey)) {
                $cooldown = $this->rateLimiter->cooldown($throttleKey);
                ContextualLogger::warning('[JWT] 频率限制触发', ['key' => $throttleKey, 'cooldown' => $cooldown]);
                return $this->respondError(
                    $request,
                    ErrorCode::THROTTLED->value,
                    '请求过于频繁，请 ' . $cooldown . ' 秒后再试',
                    null,
                    $cooldown
                );
            }
        }

        $token = $this->getExtractor($extractorNames)->extract($request);

        if (!$token) {
            // P1: 记录失败（无令牌）
            $this->recordFailure($request);
            return $this->respondError($request, ErrorCode::TOKEN_MISSING->value, '缺少认证令牌');
        }

        try {
            $payload = $jwt->parse($token);
        } catch (TokenExpiredException $e) {
            $this->recordFailure($request);
            return $this->respondError($request, $e->getCode(), $e->getMessage(), $e);
        } catch (ThrottleException $e) {
            $this->recordFailure($request);
            return $this->respondError(
                $request,
                $e->getCode(),
                '请求过于频繁，请 ' . $e->getRetryAfter() . ' 秒后再试',
                $e,
                $e->getRetryAfter()
            );
        } catch (JwtException $e) {
            $this->recordFailure($request);
            return $this->respondError($request, $e->getCode(), $e->getMessage(), $e);
        }

        // Refresh Token 不得用于业务接口鉴权：其 TTL 远长于 Access Token，
        // 直接当 Bearer 使用会绕过短效访问令牌与 Rotation 的全部设计意图。
        if (($payload['typ'] ?? '') === \wise\jwt\Jwt::TYPE_REFRESH) {
            $this->recordFailure($request);
            return $this->respondError($request, ErrorCode::TOKEN_INVALID->value, 'Refresh Token 不能用于接口鉴权');
        }

        // 鉴权成功 — 重置失败计数
        $this->clearFailure($request);

        // 注入到 request（向后兼容，P2 阶段将逐步移除直接访问）
        $request->jwt_payload = $payload;
        $request->jwt_token = $token;

        // 注入到 RequestContext（AuthManager + TokenGuard 统一获取入口）
        RequestContext::set('jwt_payload', $payload);
        RequestContext::set('jwt_token', $token);
        if (!empty($payload['user_id'])) {
            RequestContext::set('user_id', $payload['user_id']);
        }
        if (!empty($payload['sub'])) {
            RequestContext::set('jwt_sub', $payload['sub']);
        }

        // P3: 认证成功钩子（宿主可在此注入业务用户等，须在 $next 之前）
        if ($this->authenticatedHook !== null) {
            ($this->authenticatedHook)($request, $payload, $token);
        }

        $response = $next($request);

        // 自动续签
        if (($this->config['auto_refresh'] ?? true) && $jwt->shouldRefresh($payload)) {
            try {
                $newToken = $jwt->refresh($token);
                // TP8 的 Response::header() 只接受数组；传两个字符串会抛 TypeError，
                // 且原先只 catch JwtException —— 续签写入失败会把正常业务响应变成 500。
                $response->header(['X-New-Token' => $newToken]);
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

    /**
     * 构建（并按名组合缓存）提取器链
     *
     * @param string[] $names 路由级提取器名；为空则回退全局配置
     */
    protected function getExtractor(array $names = []): TokenExtractor
    {
        // 路由级配置优先，否则使用全局配置
        $names = !empty($names)
            ? $names
            : ($this->config['token']['extractors'] ?? ['bearer']);

        $cacheKey = implode(',', $names);
        if (isset($this->extractors[$cacheKey])) {
            return $this->extractors[$cacheKey];
        }

        $chain = [];
        foreach ($names as $name) {
            switch ($name) {
                case 'bearer':
                    $chain[] = new BearerHeaderExtractor(
                        $this->config['token']['header_name'] ?? 'Authorization'
                    );
                    break;
                case 'cookie':
                    $chain[] = new CookieExtractor(
                        $this->config['token']['cookie_name'] ?? 'wise_token'
                    );
                    break;
                case 'query':
                    $chain[] = new QueryExtractor(
                        $this->config['token']['query_name'] ?? 'token'
                    );
                    break;
            }
        }

        return $this->extractors[$cacheKey] = new ChainExtractor($chain);
    }

    /**
     * 输出鉴权失败响应（优先使用自定义错误响应器，缺省回退内置裸格式）。
     *
     * 以 wise-jwt 错误码（ErrorCode 枚举值，50000~50100）作为唯一判别依据：
     *   - 异常路径直接取 $exception->getCode()（过期/无效/吊销/签名/限流等均已内置）
     *   - "缺少令牌"等无异常路径传 ErrorCode::TOKEN_MISSING
     *
     * 上下文数组 $ctx：
     *   - code         wise-jwt 错误码（int）
     *   - message       错误描述
     *   - exception     原始异常（可为 null，例如"缺少令牌"）
     *   - retry_after   限流重试秒数（可选）
     *
     * @param Request        $request
     * @param int            $code       wise-jwt 错误码（ErrorCode 枚举值）
     * @param string         $message    错误描述
     * @param \Throwable|null $exception 原始异常（可为 null）
     * @param int|null       $retryAfter 限流重试秒数（可选）
     * @return Response
     */
    protected function respondError(
        Request $request,
        int $code,
        string $message,
        ?\Throwable $exception = null,
        ?int $retryAfter = null
    ): Response {
        if ($this->errorResponder !== null) {
            $response = ($this->errorResponder)($request, [
                'code'        => $code,
                'message'     => $message,
                'exception'   => $exception,
                'retry_after' => $retryAfter,
            ]);
            if ($response instanceof Response) {
                return $response;
            }
        }

        // 缺省：引擎层裸格式（不感知宿主响应协议）；限流码 → 429，令牌类 → 401
        if ($code === ErrorCode::THROTTLED->value) {
            return $this->tooManyRequests($retryAfter ?? 1);
        }

        return $this->unauthorized($message);
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
