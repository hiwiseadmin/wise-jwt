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
            fingerprinter: $this->getFingerprinter($guardConfig),
            globalRevoke: $this->config['global_revoke']['enable'] ?? false,
            fallbackSigners: $this->getFallbackSigners($name, $guardConfig),
        );
    }

    public function defaultJwt(): Jwt { return $this->guard(); }
    public function getDefaultGuard(): string { return $this->defaultGuard; }

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

        $baseKeys = ['algorithm', 'secret', 'private_key', 'public_key', 'issuer', 'audience', 'ttl', 'refresh_ttl', 'leeway', 'blacklist', 'refresh_token_ttl', 'refresh_token', 'keys', 'fingerprint'];
        $merged = [];
        foreach ($baseKeys as $key) {
            if (array_key_exists($key, $guardConfig)) {
                $merged[$key] = $guardConfig[$key];
            } elseif (array_key_exists($key, $this->config)) {
                $merged[$key] = $this->config[$key];
            }
        }

        $merged['algorithm'] = strtoupper($merged['algorithm'] ?? 'HS256');
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

    protected function getValidator(string $guardName, array $guardConfig): Validator
    {
        $cacheKey = $guardName . ':' . ($guardConfig['leeway'] ?? 0) . ':fp:' . ($this->config['fingerprint']['enable'] ?? 0);

        if (isset($this->validators[$cacheKey])) {
            return $this->validators[$cacheKey];
        }

        $leeway = (int) ($guardConfig['leeway'] ?? 0);
        $validator = new Validator($leeway);

        $validation = $this->config['validation'] ?? [];
        if ($validation['check_expiration'] ?? true) {
            $validator->addRule(new ExpirationRule($leeway));
        }
        if ($validation['check_not_before'] ?? true) {
            $validator->addRule(new NotBeforeRule($leeway));
        }
        $validator->addRule(new IssuedAtRule($leeway));

        if ($validation['check_issuer'] ?? true) {
            $validator->addRule(new IssuerRule($guardConfig['issuer']));
        }
        if ($validation['check_audience'] ?? false) {
            $audience = $guardConfig['audience'] ?? null;
            if ($audience !== null && $audience !== '') {
                $validator->addRule(new AudienceRule($audience));
            }
        }

        // ── P1: 指纹校验规则 ──
        $fingerprintConfig = $this->config['fingerprint'] ?? [];
        if ($fingerprintConfig['enable'] ?? false) {
            $fingerprinter = $this->getFingerprinter($guardConfig);
            $validator->addRule(new FingerprintRule($fingerprinter, $fingerprintConfig['strict'] ?? true));
        }

        return $this->validators[$cacheKey] = $validator;
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
}
