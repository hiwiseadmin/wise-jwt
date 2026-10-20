<?php
declare(strict_types=1);

namespace wise\jwt;

use wise\jwt\signer\SignerInterface;
use wise\jwt\validator\Validator;
use wise\jwt\blacklist\BlacklistInterface;
use wise\jwt\fingerprint\TokenFingerprinter;
use wise\jwt\exception\JwtException;
use wise\jwt\exception\TokenInvalidException;
use wise\jwt\exception\SignatureInvalidException;
use wise\jwt\exception\BlacklistedException;
use think\facade\Event as ThinkEvent;
use think\facade\Cache;
use wise\support\context\ContextualLogger;

/**
 * JWT 核心类 — 签发、校验、吊销、续签
 *
 * 支持：
 * - 单令牌模式 + 双令牌模式（Access Token + Refresh Token）
 * - 设备/IP 指纹绑定（三级安全强度）
 * - 全局令牌失效（Token Version）
 * - 密钥轮换（Kid + 多密钥验签）
 */
class Jwt
{
    public const ALG_HS256 = 'HS256';
    public const ALG_HS384 = 'HS384';
    public const ALG_HS512 = 'HS512';
    public const ALG_RS256 = 'RS256';
    public const ALG_RS384 = 'RS384';
    public const ALG_RS512 = 'RS512';
    public const ALG_ES256 = 'ES256';
    public const ALG_ES384 = 'ES384';
    public const ALG_ES512 = 'ES512';
    public const ALG_EDDSA = 'EdDSA';

    /** Refresh Token payload 中的类型标记 */
    public const TYPE_REFRESH = 'refresh';

    /** Token Version 构造 key 格式 */
    public const VERSION_KEY = 'jwt:version:%s:%s'; // issuer:subject

    /** Refresh Token 黑名单前缀（与 Access Token jti 隔离） */
    public const BLACKLIST_REFRESH_PREFIX = 'refresh:';

    /**
     * 黑名单过期时间戳上界：与 expires_at 列（无符号 INT）上限对齐
     * （2106-02-07 06:28:15 UTC），超出即视为非法入参
     */
    private const BLACKLIST_MAX_TIMESTAMP = 4294967295;

    public function __construct(
        protected string $algorithm,
        protected SignerInterface $signer,
        protected Validator $validator,
        protected ?BlacklistInterface $blacklist = null,
        protected string $issuer = 'wise-jwt',
        protected int $ttl = 7200,
        protected int $refreshTtl = 1800,
        protected ?string $audience = null,
        protected int $refreshTokenTtl = 2592000,
        protected bool $refreshTokenRotation = true,
        protected bool $refreshTokenFingerprint = false,
        // ── P1 新增参数 ──
        /** 设备指纹生成器（null 表示不绑定指纹） */
        protected ?TokenFingerprinter $fingerprinter = null,
        /** 是否全局版本失效 */
        protected bool $globalRevoke = false,
        /** 备用签名器列表（密钥轮换验签） */
        protected array $fallbackSigners = [],
        /** 令牌版本号文件持久化路径（null 表示仅依赖缓存） */
        protected ?string $versionFilePath = null,
    ) {}

    // ────────────────────────────────────────────
    //  单令牌模式（原有 API，向后兼容）
    // ────────────────────────────────────────────

    /**
     * 签发 JWT
     */
    public function issue(string|int $subject, array $claims = [], ?int $ttl = null): string
    {
        $now = time();
        $expireTtl = $ttl ?? $this->ttl;

        // 标准声明后置：iss/sub/iat/nbf/exp/jti 不可被 $claims 覆盖，
        // 防止把外部数据当作自定义声明传入时伪造身份或延长有效期。
        $payload = array_merge($claims, [
            'iss' => $this->issuer,
            'sub' => (string) $subject,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + $expireTtl,
            'jti' => $this->generateJti(),
        ]);

        $this->injectFingerprint($payload);
        $this->injectVersion($payload, (string) $subject);

        if ($this->audience !== null && !isset($payload['aud'])) {
            $payload['aud'] = $this->audience;
        }

        return $this->signPayload($payload);
    }

    /**
     * 内部方法：直接签发票据（Builder 使用，claims 已完整组装）
     */
    public function issueRaw(array $claims, int $ttl): string
    {
        $now = time();
        if (!isset($claims['exp'])) {
            $claims['exp'] = $now + $ttl;
        }
        if (!isset($claims['jti'])) {
            $claims['jti'] = $this->generateJti();
        }

        $this->injectFingerprint($claims);

        $sub = (string) ($claims['sub'] ?? '');
        if ($sub !== '') {
            $this->injectVersion($claims, $sub);
        }

        return $this->signPayload($claims);
    }

    // ────────────────────────────────────────────
    //  双令牌模式（Access Token + Refresh Token）
    // ────────────────────────────────────────────

    /**
     * 签发 Token 对（Access Token + Refresh Token）
     */
    public function issuePair(
        string|int $subject,
        array $claims = [],
        ?int $accessTtl = null,
        ?int $refreshTtl = null
    ): TokenPair {
        $accessTtl = $accessTtl ?? $this->ttl;
        $refreshTtl = $refreshTtl ?? $this->refreshTokenTtl;
        $now = time();
        $subStr = (string) $subject;

        // 签发 Access Token
        $accessToken = $this->issue($subject, $claims, $accessTtl);

        // 签发 Refresh Token
        $refreshPayload = [
            'iss'  => $this->issuer,
            'sub'  => $subStr,
            'iat'  => $now,
            'nbf'  => $now,
            'exp'  => $now + $refreshTtl,
            'jti'  => $this->generateJti(),
            'typ'  => self::TYPE_REFRESH,
        ];

        // 设备指纹绑定（独立于 access token 的指纹配置）
        if ($this->refreshTokenFingerprint && $this->fingerprinter !== null) {
            $refreshPayload['fph'] = $this->fingerprinter->generate();
        }

        // 注入全局版本号到 refresh token
        $this->injectVersion($refreshPayload, $subStr);

        if ($this->audience !== null) {
            $refreshPayload['aud'] = $this->audience;
        }

        $standardKeys = ['iss', 'sub', 'iat', 'nbf', 'exp', 'jti', 'typ', 'aud', 'fph', 'ver'];
        foreach ($claims as $k => $v) {
            if (!in_array($k, $standardKeys, true)) {
                $refreshPayload[$k] = $v;
            }
        }

        $refreshToken = $this->signPayload($refreshPayload);

        return new TokenPair(
            accessToken: $accessToken,
            refreshToken: $refreshToken,
            tokenType: 'Bearer',
            expiresIn: $accessTtl,
            refreshExpiresIn: $refreshTtl
        );
    }

    /**
     * 使用 Refresh Token 换取新的 Token 对
     */
    public function refreshAccessToken(string $refreshToken, array $customClaims = []): TokenPair
    {
        $payload = $this->parse($refreshToken);

        if (($payload['typ'] ?? '') !== self::TYPE_REFRESH) {
            throw new TokenInvalidException('非法的令牌类型，期望 Refresh Token');
        }

        $subject = (string) ($payload['sub'] ?? '');
        $oldJti = $payload['jti'] ?? '';

        if ($this->refreshTokenRotation && $this->blacklist !== null && $oldJti !== '') {
            $refreshJti = self::BLACKLIST_REFRESH_PREFIX . $oldJti;
            // 原子占位：并发请求中只有第一个能占位成功，其余一律按重放处理，
            // 消除 has()+add() 之间的 TOCTOU 窗口。
            if (!$this->blacklist->reserve($refreshJti, $payload['exp'] ?? (time() + 3600))) {
                ContextualLogger::warning('[JWT] Refresh Token 重放攻击检测', ['jti' => $oldJti, 'sub' => $subject]);
                ThinkEvent::trigger(new event\TokenInvalid($refreshToken, 'Refresh Token 重放攻击检测'));
                throw new BlacklistedException('Refresh Token 已被使用（疑似重放攻击）');
            }

            ThinkEvent::trigger(new event\TokenRevoked($oldJti));
        }

        $standardKeys = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti', 'typ', 'fph', 'ver'];
        $existingCustom = array_diff_key($payload, array_flip($standardKeys));
        $mergedClaims = array_merge($existingCustom, $customClaims);

        return $this->issuePair($subject, $mergedClaims);
    }

    /**
     * 吊销 Refresh Token
     */
    public function revokeRefreshToken(string $refreshToken): bool
    {
        try {
            $payload = $this->parse($refreshToken);
            if (($payload['typ'] ?? '') !== self::TYPE_REFRESH) {
                return false;
            }

            if ($this->blacklist !== null && isset($payload['jti'])) {
                $ok = $this->blacklist->add(self::BLACKLIST_REFRESH_PREFIX . $payload['jti'], $payload['exp'] ?? (time() + 3600));
                if (!$ok) {
                    ContextualLogger::error('[JWT] Refresh Token 吊销写入黑名单失败', ['jti' => $payload['jti']]);
                    return false;
                }
            }

            ThinkEvent::trigger(new event\TokenRevoked($payload['jti'] ?? ''));
            return true;
        } catch (JwtException) {
            return false;
        }
    }

    // ────────────────────────────────────────────
    //  解码（不验签）
    // ────────────────────────────────────────────

    /**
     * 仅解码 JWT payload，不验签、不校验、不查黑名单
     *
     * 注意：此方法不进行任何安全校验，返回的 payload 不可信。
     * 仅适用于调试或需要在验签前读取 header 的场景。
     *
     * @return array|null payload 数组，解码失败返回 null
     */
    public function decode(string $token): ?array
    {
        $result = $this->decodeFull($token);
        return $result['payload'] ?? null;
    }

    /**
     * 仅解码 JWT header，不验签
     *
     * @return array|null header 数组（含 alg/typ/kid 等），解码失败返回 null
     */
    public function decodeHeader(string $token): ?array
    {
        $result = $this->decodeFull($token);
        return $result['header'] ?? null;
    }

    /**
     * 解码 JWT 的 header + payload，不验签
     *
     * 严格检查 JWT 标准三段式格式。
     *
     * @return array{header: array|null, payload: array|null}|null
     */
    public function decodeFull(string $token): ?array
    {
        $segments = explode('.', $token);
        if (count($segments) !== 3) {
            return null;
        }

        [$headerB64, $payloadB64] = $segments;

        $headerDecoded = $this->base64UrlDecode($headerB64);
        $header = json_decode($headerDecoded, true);
        if (!is_array($header)) {
            $header = null;
        }

        $payloadDecoded = $this->base64UrlDecode($payloadB64);
        $payload = json_decode($payloadDecoded, true);
        if (!is_array($payload)) {
            $payload = null;
        }

        return ['header' => $header, 'payload' => $payload];
    }

    // ────────────────────────────────────────────
    //  解析与校验
    // ────────────────────────────────────────────

    /**
     * 解析并校验 JWT
     */
    public function parse(string $token): array
    {
        ThinkEvent::trigger(new event\TokenParsing($token));

        $segments = explode('.', $token);
        if (count($segments) !== 3) {
            ThinkEvent::trigger(new event\TokenInvalid($token, '令牌格式错误'));
            throw new TokenInvalidException('令牌格式错误');
        }

        [$headerB64, $payloadB64, $signatureB64] = $segments;

        // 解码
        $header = json_decode($this->base64UrlDecode($headerB64), true);
        $payload = json_decode($this->base64UrlDecode($payloadB64), true);

        if (!$header || !$payload) {
            ThinkEvent::trigger(new event\TokenInvalid($token, '令牌编码无效'));
            throw new TokenInvalidException('令牌编码无效');
        }

        // 验证算法匹配
        $tokenAlg = $header['alg'] ?? '';
        if ($tokenAlg !== $this->algorithm) {
            ContextualLogger::warning('[JWT] 算法不匹配', ['expected' => $this->algorithm, 'got' => $tokenAlg, 'sub' => $payload['sub'] ?? 'unknown']);
            ThinkEvent::trigger(new event\TokenInvalid($token, "算法不匹配: {$tokenAlg}"));
            throw new SignatureInvalidException('算法不匹配');
        }

        // 验证签名（主密钥 + 备用密钥轮换）
        $signatureRaw = $this->base64UrlDecode($signatureB64);
        $verified = $this->signer->verify($headerB64, $payloadB64, $signatureRaw);

        if (!$verified && !empty($this->fallbackSigners)) {
            $tokenKid = $header['kid'] ?? null;
            foreach ($this->fallbackSigners as $fbSigner) {
                // kid 匹配优先
                if ($tokenKid !== null && $fbSigner->kid() !== $tokenKid) {
                    continue;
                }
                if ($fbSigner->verify($headerB64, $payloadB64, $signatureRaw)) {
                    $verified = true;
                    break;
                }
            }
        }

        if (!$verified) {
            ContextualLogger::warning('[JWT] 签名验证失败', ['sub' => $payload['sub'] ?? 'unknown', 'alg' => $tokenAlg]);
            ThinkEvent::trigger(new event\TokenInvalid($token, '签名验证失败'));
            throw new SignatureInvalidException('签名验证失败');
        }

        // 检查黑名单（同时检查 Access Token 和 Refresh Token 隔离的黑名单）
        if ($this->blacklist !== null && isset($payload['jti'])) {
            $rawJti = $payload['jti'];
            if ($this->blacklist->has($rawJti) || $this->blacklist->has(self::BLACKLIST_REFRESH_PREFIX . $rawJti)) {
                ThinkEvent::trigger(new event\TokenInvalid($token, '令牌已被吊销'));
                throw new BlacklistedException('令牌已被吊销');
            }
        }

        // 校验全局版本号
        $this->checkVersion($payload);

        // 执行声明校验（含指纹校验）
        try {
            $this->validator->validate($payload);
        } catch (JwtException $e) {
            ThinkEvent::trigger(new event\TokenInvalid($token, $e->getMessage()));
            throw $e;
        }

        ThinkEvent::trigger(new event\TokenParsed($token, $payload));
        return $payload;
    }

    public function tryParse(string $token): ?array
    {
        try {
            return $this->parse($token);
        } catch (JwtException) {
            return null;
        }
    }

    public function ttlOf(array $payload): int
    {
        $exp = $payload['exp'] ?? 0;
        return max(0, $exp - time());
    }

    public function shouldRefresh(array $payload): bool
    {
        $exp = $payload['exp'] ?? 0;
        return $exp > 0 && ($exp - time()) < $this->refreshTtl;
    }

    public function refresh(string $token): string
    {
        // 必须先通过完整的 parse() 校验（签名、黑名单、声明、指纹等）
        $payload = $this->parse($token);

        // 未进入续签窗口（剩余有效期 >= refresh_ttl）不允许续签，
        // 否则令牌可被无限制续期，TTL 形同虚设。
        if (!$this->shouldRefresh($payload)) {
            throw new TokenInvalidException('未进入续签窗口，不允许续签');
        }

        if ($this->blacklist !== null && isset($payload['jti'])) {
            $this->blacklist->add($payload['jti'], $payload['exp'] ?? (time() + 3600));
        }

        $standardKeys = ['iss', 'sub', 'aud', 'iat', 'nbf', 'exp', 'jti', 'typ', 'fph', 'ver'];
        $customClaims = array_diff_key($payload, array_flip($standardKeys));

        return $this->issue((string) ($payload['sub'] ?? ''), $customClaims);
    }

    public function revoke(string $token): bool
    {
        try {
            $payload = $this->parse($token);
            if (!isset($payload['jti'])) {
                return false;
            }

            if ($this->blacklist !== null) {
                $ok = $this->blacklist->add($payload['jti'], $payload['exp'] ?? (time() + 3600));
                if (!$ok) {
                    ContextualLogger::error('[JWT] 吊销写入黑名单失败，令牌仍可能有效', ['jti' => $payload['jti']]);
                    return false;
                }
            }

            ThinkEvent::trigger(new event\TokenRevoked($payload['jti']));
            return true;
        } catch (JwtException) {
            return false;
        }
    }

    /**
     * 批量吊销 token
     *
     * @param string[] $tokens
     * @return int 成功吊销的数量
     */
    public function revokeMany(array $tokens): int
    {
        if ($this->blacklist === null || empty($tokens)) {
            return 0;
        }

        $count = 0;
        foreach ($tokens as $token) {
            try {
                $payload = $this->parse($token);
                if (!isset($payload['jti'])) {
                    continue;
                }

                if (!$this->blacklist->add($payload['jti'], $payload['exp'] ?? (time() + 3600))) {
                    ContextualLogger::error('[JWT] 批量吊销写入黑名单失败', ['jti' => $payload['jti']]);
                    continue;
                }
                ThinkEvent::trigger(new event\TokenRevoked($payload['jti']));
                $count++;
            } catch (JwtException) {
                continue;
            }
        }

        return $count;
    }

    public function isRevoked(string $jti): bool
    {
        if ($this->blacklist === null || $jti === '') {
            return false;
        }

        // 与 parse() 的黑名单检查保持一致：Access Token 与 Refresh Token 使用隔离的
        // 命名空间，两者都要查。否则 refresh jti 会出现「parse() 拦截但 isRevoked()
        // 返回 false」的自相矛盾。
        return $this->blacklist->has($jti)
            || $this->blacklist->has(self::BLACKLIST_REFRESH_PREFIX . $jti);
    }

    /**
     * 按 jti 直接吊销（无完整 token 时使用）
     *
     * @param string $jti       令牌 ID
     * @param int    $expiresAt 黑名单过期时间戳（Unix 秒），非法时回退为默认 30 天后
     */
    public function revokeByJti(string $jti, int $expiresAt = 0): bool
    {
        if ($this->blacklist === null) {
            return false;
        }

        // 入参加固：expires_at 列是无符号 INT，且黑名单记录必须在「未来」过期才有意义。
        // - 过小（负数 / 已过去的时刻）：记录会被 purge() 立即清掉，等于没吊销；
        // - 过大（如调用方误传毫秒时间戳）：写入无符号 INT 越界，严格模式下报错导致吊销失败。
        // 因此只接受 (now, BLACKLIST_MAX_TIMESTAMP] 区间内的秒级时间戳，其余一律回退默认 30 天。
        // 注意：0 是「未显式传入」的默认值，属正常用法，不告警。
        if ($expiresAt !== 0 && ($expiresAt <= time() || $expiresAt > self::BLACKLIST_MAX_TIMESTAMP)) {
            ContextualLogger::warning('[JWT] revokeByJti 收到非法 expiresAt，已回退为默认 30 天', [
                'jti'       => $jti,
                'expiresAt' => $expiresAt,
            ]);
            $expiresAt = 0;
        }

        if ($expiresAt === 0) {
            $expiresAt = time() + 2592000;
        }

        return $this->blacklist->add($jti, $expiresAt);
    }

    // ────────────────────────────────────────────
    //  全局令牌失效（Token Version）
    // ────────────────────────────────────────────

    /**
     * 撤销指定用户的所有令牌（递增版本号）
     *
     * 双写策略：Cache + File，即使 cache:clear 也不会丢失版本号。
     *
     * @param string $subject 用户标识
     * @return int 新版本号
     */
    public function revokeAllBySubject(string $subject): int
    {
        $versionKey = $this->getVersionCacheKey($subject);
        $newVersion = $this->getVersion($subject) + 1;

        // 双写：Cache（热读取）+ File（持久化防丢失）
        Cache::set($versionKey, $newVersion);
        $this->writeVersionToFile($subject, $newVersion);

        ContextualLogger::info('[JWT] 全局吊销用户令牌', ['sub' => $subject, 'new_version' => $newVersion]);
        return $newVersion;
    }

    /**
     * 获取用户的当前令牌版本号
     *
     * 读取顺序：Cache（热）→ File（冷持久化）→ 回写 Cache。
     */
    public function getVersion(string $subject): int
    {
        $cacheKey = $this->getVersionCacheKey($subject);
        $version = Cache::get($cacheKey);

        if ($version !== null) {
            return (int) $version;
        }

        // Cache miss — 从文件持久化层恢复
        $version = $this->readVersionFromFile($subject);

        // 回写 Cache（零过期，永不过期，仅 cache:clear 会清除）
        Cache::set($cacheKey, $version);

        return $version;
    }

    /**
     * 设置用户的令牌版本号
     *
     * 双写策略：Cache + File。
     */
    public function setVersion(string $subject, int $version): void
    {
        Cache::set($this->getVersionCacheKey($subject), $version);
        $this->writeVersionToFile($subject, $version);
    }

    /**
     * 注入版本号到 payload
     */
    protected function injectVersion(array &$payload, string $subject): void
    {
        if ($this->globalRevoke) {
            $payload['ver'] = $this->getVersion($subject);
        }
    }

    /**
     * 检查 payload 中的版本号
     */
    protected function checkVersion(array $payload): void
    {
        if (!$this->globalRevoke || !isset($payload['sub'])) {
            return;
        }

        $currentVersion = $this->getVersion($payload['sub']);

        // 缺 ver（含开关开启前签发的历史令牌）或版本不等于当前版本一律拒绝，
        // 避免"无版本号即免检"与版本号回退导致的 fail-open。
        if (!isset($payload['ver']) || (int) $payload['ver'] !== $currentVersion) {
            ContextualLogger::info('[JWT] 令牌版本已失效', ['sub' => $payload['sub'], 'token_ver' => $payload['ver'] ?? null, 'current_ver' => $currentVersion]);
            throw new TokenInvalidException('令牌已全局失效');
        }
    }

    /**
     * 获取版本号缓存键
     */
    protected function getVersionCacheKey(string $subject): string
    {
        return sprintf(self::VERSION_KEY, $this->issuer, $subject);
    }

    /**
     * 获取版本号文件持久化路径
     *
     * 文件名格式：{issuer}_{md5(subject)}.json
     * 对 subject 做 md5 避免文件名特殊字符问题。
     */
    protected function getVersionFilePath(string $subject): string
    {
        $dir = $this->versionFilePath;
        return $dir . $this->issuer . '_' . md5($subject) . '.json';
    }

    /**
     * 从文件持久化层读取版本号
     *
     * @return int 版本号，未找到文件返回 0
     */
    protected function readVersionFromFile(string $subject): int
    {
        if ($this->versionFilePath === null) {
            return 0;
        }

        $filePath = $this->getVersionFilePath($subject);
        if (!file_exists($filePath)) {
            return 0;
        }

        $data = json_decode(file_get_contents($filePath), true);
        return (int) ($data['version'] ?? 0);
    }

    /**
     * 写入版本号到文件持久化层
     *
     * 自动创建目录，静默处理 IO 错误。
     */
    protected function writeVersionToFile(string $subject, int $version): void
    {
        if ($this->versionFilePath === null) {
            return;
        }

        try {
            $filePath = $this->getVersionFilePath($subject);
            $dir = dirname($filePath);
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }

            file_put_contents($filePath, json_encode([
                'issuer'     => $this->issuer,
                'subject'    => $subject,
                'version'    => $version,
                'updated_at' => date('Y-m-d H:i:s'),
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        } catch (\Throwable $e) {
            // 文件写入失败不阻塞业务流程
            ContextualLogger::error('[JWT] 版本号文件持久化失败', ['sub' => $subject, 'version' => $version, 'error' => $e->getMessage()]);
        }
    }

    // ────────────────────────────────────────────
    //  指纹绑定
    // ────────────────────────────────────────────

    /**
     * 注入设备指纹到 payload
     */
    protected function injectFingerprint(array &$payload): void
    {
        if ($this->fingerprinter !== null && !isset($payload['fph'])) {
            $payload['fph'] = $this->fingerprinter->generate();
        }
    }

    // ────────────────────────────────────────────
    //  密钥轮换
    // ────────────────────────────────────────────

    /**
     * 添加备用签名器（密钥轮换用）
     */
    public function addFallbackSigner(SignerInterface $signer): self
    {
        $this->fallbackSigners[] = $signer;
        return $this;
    }

    /**
     * 设置备用签名器列表
     */
    public function setFallbackSigners(array $signers): self
    {
        $this->fallbackSigners = $signers;
        return $this;
    }

    /**
     * 获取所有签名器（含主密钥和备用密钥）
     */
    public function getAllSigners(): array
    {
        return array_merge([$this->signer], $this->fallbackSigners);
    }

    // ────────────────────────────────────────────
    //  Builder + Getter
    // ────────────────────────────────────────────

    public function builder(): Builder
    {
        return new Builder($this);
    }

    public function getAlgorithm(): string     { return $this->algorithm; }
    public function getIssuer(): string         { return $this->issuer; }
    public function getTtl(): int               { return $this->ttl; }
    public function getRefreshTokenTtl(): int   { return $this->refreshTokenTtl; }
    public function getFingerprinter(): ?TokenFingerprinter { return $this->fingerprinter; }
    public function isGlobalRevokeEnabled(): bool { return $this->globalRevoke; }

    // ────────────────────────────────────────────
    //  内部工具方法
    // ────────────────────────────────────────────

    /**
     * 对完整的 payload 执行 Base64URL 编码 + 签名，返回完整 token 字符串。
     *
     * 统一 issue() / issueRaw() / issuePair() 的签名流程，避免重复代码。
     */
    protected function signPayload(array $payload): string
    {
        ThinkEvent::trigger(new event\TokenIssuing($payload));

        $header = ['alg' => $this->algorithm, 'typ' => 'JWT'];
        if ($kid = $this->signer->kid()) {
            $header['kid'] = $kid;
        }
        $headerB64 = $this->base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES));
        $payloadB64 = $this->base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES));
        $signature = $this->signer->sign($headerB64, $payloadB64);
        $signatureB64 = $this->base64UrlEncode($signature);

        $token = implode('.', [$headerB64, $payloadB64, $signatureB64]);

        ThinkEvent::trigger(new event\TokenIssued($token, $payload));
        return $token;
    }

    /**
     * 运行时覆盖 Refresh Token Rotation 设置（Builder 使用）
     */
    public function setRotation(bool $enabled): self
    {
        $this->refreshTokenRotation = $enabled;
        return $this;
    }

    /**
     * 运行时覆盖 Refresh Token 指纹绑定（Builder 使用）
     */
    public function setRefreshTokenFingerprint(bool $enabled): self
    {
        $this->refreshTokenFingerprint = $enabled;
        return $this;
    }

    /**
     * 运行时覆盖 audience（Builder 使用）
     */
    public function setAudience(?string $audience): self
    {
        $this->audience = $audience;
        return $this;
    }

    /**
     * 获取黑名单实例（命令/管理工具使用）
     */
    public function getBlacklist(): ?BlacklistInterface
    {
        return $this->blacklist;
    }

    protected function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }

    protected function base64UrlEncode(string $data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    protected function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(str_replace(['-', '_'], ['+', '/'], $data));
        return $decoded !== false ? $decoded : '';
    }
}
