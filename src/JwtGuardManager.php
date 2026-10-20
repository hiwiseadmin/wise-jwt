<?php
declare(strict_types=1);

namespace wise\jwt;

use wise\jwt\signer\SignerInterface;
use wise\jwt\signer\SignerFactory;
use wise\jwt\validator\Validator;
use wise\jwt\validator\ExpirationRule;
use wise\jwt\validator\NotBeforeRule;
use wise\jwt\validator\IssuedAtRule;
use wise\jwt\validator\IssuerRule;
use wise\jwt\validator\AudienceRule;
use wise\jwt\fingerprint\TokenFingerprinter;
use wise\jwt\fingerprint\FingerprintRule;
use wise\jwt\blacklist\BlacklistInterface;
use wise\jwt\blacklist\CacheBlacklist;
use wise\jwt\blacklist\RedisBlacklist;
use wise\jwt\blacklist\DatabaseBlacklist;
use wise\jwt\exception\JwtException;

/**
 * JWT Guard 管理器 — 按 guard 名获取独立配置的 Jwt 实例
 *
 * 支持：
 * - 多 Guard 独立配置
 * - 密钥轮换（keys 配置，主密钥签名 + 备用密钥验签）
 * - 设备指纹绑定
 * - 全局令牌失效
 * - 数据库黑名单
 */
class JwtGuardManager
{
    protected array $config;
    protected string $defaultGuard;

    /** @var array<string, Jwt> 已解析的 guard 实例缓存 */
    protected array $resolved = [];

    /** @var array<string, Validator> Validator 缓存 */
    protected array $validators = [];

    /** @var array<string, SignerInterface> Signer 缓存 */
    protected array $signers = [];

    /** @var array<string, ?BlacklistInterface> Blacklist 缓存 */
    protected array $blacklists = [];

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->defaultGuard = $config['default'] ?? 'app';
    }

    /**
     * 获取指定 guard 的 Jwt 实例
     */
    public function guard(?string $name = null): Jwt
    {
        $name = $name ?? $this->defaultGuard;

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        $guardConfig = $this->getGuardConfig($name);

        // refresh_token.* 为「分组式」配置写法，必须显式接线到 Jwt 构造参数，
        // 否则配置里写着 fingerprint=true 而引擎恒为 false（安全开关静默失效）。
        $refreshToken = $guardConfig['refresh_token'] ?? [];

        return $this->resolved[$name] = new Jwt(
            algorithm: $guardConfig['algorithm'],
            signer: $this->getSigner($name, $guardConfig),
            validator: $this->getValidator($name, $guardConfig),
            blacklist: $this->getBlacklist($name, $guardConfig),
            issuer: $guardConfig['issuer'],
            ttl: $guardConfig['ttl'],
            refreshTtl: $guardConfig['refresh_ttl'] ?? 1800,
            audience: $guardConfig['audience'] ?? null,
            refreshTokenTtl: $guardConfig['refresh_token_ttl'] ?? 2592000,
            // ── P1 新增参数 ──
            refreshTokenRotation: (bool) ($refreshToken['enable'] ?? true),
            refreshTokenFingerprint: (bool) ($refreshToken['fingerprint'] ?? false),
            fingerprinter: $this->getFingerprinter($guardConfig),
            globalRevoke: $this->config['global_revoke']['enable'] ?? false,
            fallbackSigners: $this->getFallbackSigners($name, $guardConfig),
            versionFilePath: $this->getVersionFilePath(),
        );
    }

    public function defaultJwt(): Jwt { return $this->guard(); }
    public function getDefaultGuard(): string { return $this->defaultGuard; }

    /**
     * 该 guard 是否已在 wise-jwt.guards 中配置
     *
     * 供 ExtPoint('jwt.provider') 判断能否返回守卫专属引擎：未配置的 guard
     * 必须回退默认引擎，否则 TokenGuard('api') 这类命名守卫会因缺少
     * guards.api 配置而全部认证失败（guard() 对未配置的 guard 会抛异常）。
     */
    public function hasGuard(string $name): bool
    {
        return isset($this->config['guards'][$name]) && is_array($this->config['guards'][$name]);
    }

    public function flush(?string $name = null): void
    {
        if ($name !== null) {
            unset($this->resolved[$name], $this->validators[$name], $this->signers[$name], $this->blacklists[$name]);
        } else {
            $this->resolved = [];
            $this->validators = [];
            $this->signers = [];
            $this->blacklists = [];
        }
    }

    // ── 配置合并 ──

    protected function getGuardConfig(string $name): array
    {
        $guardConfig = $this->config['guards'][$name] ?? null;

        if ($guardConfig === null) {
            throw new JwtException("JWT Guard '{$name}' 未配置");
        }

        // 密钥类键同时纳入 _base64 / _file 变体，保证守卫级配置可继承顶层
        $baseKeys = [
            'algorithm',
            'secret', 'secret_base64', 'secret_file',
            'private_key', 'private_key_base64', 'private_key_file',
            'public_key', 'public_key_base64', 'public_key_file',
            'issuer', 'audience', 'ttl', 'refresh_ttl', 'leeway',
            'blacklist', 'refresh_token_ttl', 'refresh_token', 'keys', 'fingerprint',
        ];
        $merged = [];
        foreach ($baseKeys as $key) {
            $guardVal = $guardConfig[$key] ?? null;
            $hasGuard = array_key_exists($key, $guardConfig);

            // 守卫级「非空值」优先；空值视为未覆盖，回退继承顶层配置。
            // 约定见 config/wise-jwt.php：guards.app.secret 留空即自动继承顶层 secret。
            if ($hasGuard && !self::isBlank($guardVal)) {
                $merged[$key] = $guardVal;
            } elseif (array_key_exists($key, $this->config)) {
                $merged[$key] = $this->config[$key];
            }
        }

        // EdDSA 的注册标识为混合大小写（RFC 8037），其余算法统一大写。
        // 一律 strtoupper 会写出 {"alg":"EDDSA"}，与标准库互操作时被判为不支持的算法。
        $alg = (string) ($merged['algorithm'] ?? 'HS256');
        $merged['algorithm'] = strcasecmp($alg, 'EdDSA') === 0 ? 'EdDSA' : strtoupper($alg);
        $merged['secret'] = (string) ($merged['secret'] ?? '');
        $merged['private_key'] = (string) ($merged['private_key'] ?? '');
        $merged['public_key'] = (string) ($merged['public_key'] ?? '');
        $merged['issuer'] = (string) ($merged['issuer'] ?? 'wiseadmin');
        $merged['ttl'] = (int) ($merged['ttl'] ?? 7200);
        $merged['refresh_ttl'] = (int) ($merged['refresh_ttl'] ?? 1800);
        $merged['refresh_token_ttl'] = (int) ($merged['refresh_token_ttl'] ?? 2592000);
        $merged['audience'] = isset($merged['audience']) && $merged['audience'] !== '' ? (string) $merged['audience'] : null;

        return $merged;
    }

    /**
     * 判断守卫级配置值是否"留空"（空字符串 / null / 空数组）。
     *
     * 留空即视为未覆盖该键，允许回退继承顶层配置。
     */
    private static function isBlank(mixed $value): bool
    {
        return $value === null || $value === '' || $value === [];
    }

    // ── Signer（含密钥轮换） ──

    protected function getSigner(string $guardName, array $guardConfig): SignerInterface
    {
        $cacheKey = $guardName . ':' . ($guardConfig['algorithm'] ?? 'HS256') . ':active';

        if (isset($this->signers[$cacheKey])) {
            return $this->signers[$cacheKey];
        }

        // 如果有 keys 配置（密钥轮换），使用第一个 active 的 key
        $keys = $guardConfig['keys'] ?? [];
        if (!empty($keys)) {
            foreach ($keys as $key) {
                if ($key['active'] ?? false) {
                    return $this->signers[$cacheKey] = $this->createSignerFromKey($guardConfig['algorithm'], $key);
                }
            }
            // 没有 active key，使用第一个
            return $this->signers[$cacheKey] = $this->createSignerFromKey($guardConfig['algorithm'], reset($keys));
        }

        return $this->signers[$cacheKey] = $this->createSigner($guardConfig);
    }

    /**
     * 获取备用签名器列表（密钥轮换验签用）
     */
    protected function getFallbackSigners(string $guardName, array $guardConfig): array
    {
        $keys = $guardConfig['keys'] ?? [];
        if (empty($keys)) {
            return [];
        }

        $fallbacks = [];
        $alg = $guardConfig['algorithm'];

        foreach ($keys as $key) {
            // active key 由主 signer 处理，其余为 fallback
            if ($key['active'] ?? false) {
                continue;
            }
            $fallbacks[] = $this->createSignerFromKey($alg, $key);
        }

        return $fallbacks;
    }

    /**
     * 从单个 key 配置创建签名器
     */
    protected function createSignerFromKey(string $alg, array $keyConfig): SignerInterface
    {
        $signer = $this->newSigner($alg, $keyConfig);

        // 设置 kid
        if (method_exists($signer, 'setKid') && isset($keyConfig['kid'])) {
            $signer->setKid($keyConfig['kid']);
        }

        return $signer;
    }

    /**
     * 创建签名器实例（无 kid）
     */
    protected function newSigner(string $alg, array $config): SignerInterface
    {
        return SignerFactory::create($alg, $config);
    }

    protected function createSigner(array $config): SignerInterface
    {
        return $this->newSigner($config['algorithm'] ?? 'HS256', $config);
    }

    // ── Validator（含指纹校验） ──

    /**
     * 根据完整配置构建 Validator（公共静态方法，ServiceProvider 复用）
     *
     * @param array $config 完整的 wise-jwt 配置（顶层，含 validation/fingerprint/issuer/audience 等）
     */
    public static function buildValidatorFromConfig(array $config): Validator
    {
        $leeway = (int) ($config['leeway'] ?? 0);
        $validator = new Validator($leeway);

        $validation = $config['validation'] ?? [];
        if ($validation['check_expiration'] ?? true) {
            $validator->addRule(new ExpirationRule($leeway));
        }
        if ($validation['check_not_before'] ?? true) {
            $validator->addRule(new NotBeforeRule($leeway));
        }
        // 尊重配置文件中的 check_issued_at 开关（此前该项恒被注册，配置无效）
        if ($validation['check_issued_at'] ?? true) {
            $validator->addRule(new IssuedAtRule($leeway));
        }

        if ($validation['check_issuer'] ?? true) {
            $issuer = $config['issuer'] ?? 'wiseadmin';
            $validator->addRule(new IssuerRule($issuer));
        }
        if ($validation['check_audience'] ?? false) {
            $audience = $config['audience'] ?? null;
            if ($audience !== null && $audience !== '') {
                $validator->addRule(new AudienceRule($audience));
            }
        }

        // 指纹校验规则
        $fpConfig = $config['fingerprint'] ?? [];
        if ($fpConfig['enable'] ?? false) {
            $level = $fpConfig['level'] ?? TokenFingerprinter::LEVEL_MEDIUM;
            $fingerprinter = new TokenFingerprinter($level);
            $validator->addRule(new FingerprintRule($fingerprinter, $fpConfig['strict'] ?? true));
        }

        // 注入全局注册的自定义规则
        $validator->applyRegisteredRules();

        return $validator;
    }

    protected function getValidator(string $guardName, array $guardConfig): Validator
    {
        $cacheKey = $guardName . ':' . ($guardConfig['leeway'] ?? 0) . ':fp:' . ($this->config['fingerprint']['enable'] ?? 0);

        if (isset($this->validators[$cacheKey])) {
            return $this->validators[$cacheKey];
        }

        // 合并 guard 级配置进入顶层 config 用于 buildValidatorFromConfig
        $mergedConfig = array_merge($this->config, [
            'leeway'   => $guardConfig['leeway'] ?? $this->config['leeway'] ?? 0,
            'issuer'   => $guardConfig['issuer'] ?? $this->config['issuer'] ?? 'wiseadmin',
            'audience' => $guardConfig['audience'] ?? $this->config['audience'] ?? null,
        ]);

        return $this->validators[$cacheKey] = self::buildValidatorFromConfig($mergedConfig);
    }

    // ── Blacklist（含数据库驱动） ──

    protected function getBlacklist(string $guardName, array $guardConfig): ?BlacklistInterface
    {
        $blConfig = $guardConfig['blacklist'] ?? $this->config['blacklist'] ?? [];
        if (!($blConfig['enable'] ?? true)) {
            return null;
        }

        $driver = $blConfig['driver'] ?? 'cache';
        $prefix = $blConfig['prefix'] ?? 'jwt:blacklist:';
        $table = $blConfig['db_table'] ?? 'jwt_blacklist';
        $cacheKey = $guardName . ':' . $driver . ':' . $prefix;

        if (array_key_exists($cacheKey, $this->blacklists)) {
            return $this->blacklists[$cacheKey];
        }

        return $this->blacklists[$cacheKey] = match ($driver) {
            'redis'    => new RedisBlacklist($prefix),
            'database' => new DatabaseBlacklist($prefix, $table),
            default    => new CacheBlacklist($prefix),
        };
    }

    // ── Fingerprint ──

    protected function getFingerprinter(array $guardConfig): ?TokenFingerprinter
    {
        $fpConfig = $this->config['fingerprint'] ?? [];
        if (!($fpConfig['enable'] ?? false)) {
            return null;
        }

        $level = $fpConfig['level'] ?? TokenFingerprinter::LEVEL_MEDIUM;
        return new TokenFingerprinter($level);
    }

    // ── Version Persistence ──

    /**
     * 获取令牌版本号文件持久化路径
     *
     * 返回 null 表示不启用文件持久化（仅依赖缓存存储）。
     */
    protected function getVersionFilePath(): ?string
    {
        $vpConfig = $this->config['version_persistence'] ?? [];
        if (!($vpConfig['enable'] ?? true)) {
            return null;
        }

        $customPath = $vpConfig['file_path'] ?? '';
        if ($customPath !== '') {
            return rtrim($customPath, '/\\') . '/';
        }

        // 默认使用 runtime/wise-jwt/version/（不随 cache:clear 丢失）
        //
        // runtime_path() 是 ThinkPHP 全局助手，仅在框架 helper 已加载时存在；
        // 在单元测试、独立 CLI 脚本等无框架引导的场景下需降级，避免直接
        // Error: Call to undefined function。
        if (function_exists('runtime_path')) {
            $runtime = runtime_path();
        } elseif (defined('ROOT_PATH')) {
            $runtime = ROOT_PATH . 'runtime' . DIRECTORY_SEPARATOR;
        } else {
            $runtime = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
        }

        return $runtime . 'wise-jwt' . DIRECTORY_SEPARATOR . 'version' . DIRECTORY_SEPARATOR;
    }
}
