<?php
declare(strict_types=1);

namespace wise\jwt;

use think\App;
use think\Service as BaseService;
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
use wise\jwt\throttle\RateLimiter;
use wise\jwt\blacklist\BlacklistInterface;
use wise\jwt\blacklist\CacheBlacklist;
use wise\jwt\blacklist\RedisBlacklist;
use wise\jwt\blacklist\DatabaseBlacklist;
use wise\jwt\trait\ServiceTrait;

/**
 * wise-jwt 服务注册 — 支持多 Guard + 双令牌模式 + P1 安全增强
 */
class Service extends BaseService
{
    use ServiceTrait;

    public function register(): void
    {
        $this->mergeConfig('wise-jwt');

        // ── 注册 JwtGuardManager（多 Guard 工厂） ──
        $this->app->bind(JwtGuardManager::class, function (App $app) {
            return new JwtGuardManager($app->config->get('wise-jwt', []));
        });

        // ── 绑定默认 Jwt（兼容旧版单例模式） ──
        $this->app->bind(Jwt::class, function (App $app) {
            return $app->make(JwtGuardManager::class)->defaultJwt();
        });

        // ── 绑定默认 SignerInterface ──
        $this->app->bind(SignerInterface::class, function (App $app) {
            $config = $app->config->get('wise-jwt', []);
            $alg = strtoupper($config['algorithm'] ?? 'HS256');
            return SignerFactory::create($alg, $config);
        });

        // ── 绑定默认 Validator ──
        $this->app->bind(Validator::class, function (App $app) {
            $config = $app->config->get('wise-jwt', []);
            $leeway = (int) ($config['leeway'] ?? 0);
            $validator = new Validator($leeway);

            $validation = $config['validation'] ?? [];
            if ($validation['check_expiration'] ?? true) {
                $validator->addRule(new ExpirationRule($leeway));
            }
            if ($validation['check_not_before'] ?? true) {
                $validator->addRule(new NotBeforeRule($leeway));
            }
            if ($validation['check_issued_at'] ?? true) {
                $validator->addRule(new IssuedAtRule($leeway));
            }

            if ($validation['check_issuer'] ?? true) {
                $issuer = $config['issuer'] ?? 'wiseadmin';
                $validator->addRule(new IssuerRule($issuer));
            }
            if ($validation['check_audience'] ?? false) {
                $audience = $config['audience'] ?? '';
                if ($audience !== '') {
                    $validator->addRule(new AudienceRule($audience));
                }
            }

            // ── P1: 指纹校验规则 ──
            $fingerprintConfig = $config['fingerprint'] ?? [];
            if ($fingerprintConfig['enable'] ?? false) {
                $level = $fingerprintConfig['level'] ?? TokenFingerprinter::LEVEL_MEDIUM;
                $fingerprinter = new TokenFingerprinter($level);
                $validator->addRule(new FingerprintRule(
                    $fingerprinter,
                    $fingerprintConfig['strict'] ?? true
                ));
            }

            return $validator;
        });

        // ── 绑定默认 BlacklistInterface（支持 database 驱动） ──
        $this->app->bind(BlacklistInterface::class, function (App $app) {
            $config = $app->config->get('wise-jwt.blacklist', []);
            $driver = $config['driver'] ?? 'cache';
            $prefix = $config['prefix'] ?? 'jwt:blacklist:';

            return match ($driver) {
                'redis'    => new RedisBlacklist($prefix),
                'database' => new DatabaseBlacklist($prefix, $config['db_table'] ?? 'jwt_blacklist'),
                default    => new CacheBlacklist($prefix),
            };
        });

        // ── P1: 绑定 P1 组件到容器 ──
        $this->app->bind(TokenFingerprinter::class, function (App $app) {
            $config = $app->config->get('wise-jwt.fingerprint', []);
            return new TokenFingerprinter($config['level'] ?? TokenFingerprinter::LEVEL_MEDIUM);
        });

        $this->app->bind(RateLimiter::class, function (App $app) {
            $config = $app->config->get('wise-jwt.throttle', []);
            return new RateLimiter(
                (int) ($config['max_attempts'] ?? 5),
                (int) ($config['decay_seconds'] ?? 60),
                $config['prefix'] ?? 'jwt:throttle:'
            );
        });

        // ── 绑定中间件（使用默认 Guard） ──
        $this->app->bind('jwt.auth', function (App $app) {
            return new middleware\JwtAuth(
                $app->make(JwtGuardManager::class),
                $app->config->get('wise-jwt', [])
            );
        });
    }
}
