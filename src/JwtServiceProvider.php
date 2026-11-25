<?php
declare(strict_types=1);

namespace wise\jwt;

use think\App;
use think\Service as BaseService;
use wise\jwt\signer\SignerInterface;
use wise\jwt\signer\SignerFactory;
use wise\jwt\validator\Validator;
use wise\jwt\fingerprint\TokenFingerprinter;
use wise\jwt\throttle\RateLimiter;
use wise\jwt\blacklist\BlacklistInterface;
use wise\jwt\blacklist\CacheBlacklist;
use wise\jwt\blacklist\RedisBlacklist;
use wise\jwt\blacklist\DatabaseBlacklist;
use wise\support\traits\ServiceTrait;
use wise\support\config\ConfigCheckCollector;
use wise\support\contracts\EnvSeedProvider;
use wise\support\ExtPoint;
use wise\support\ExtPoints;
use wise\jwt\config\JwtSecretCheck;
use wise\support\context\ContextualLogger;

/**
 * wise-jwt 服务注册 — 支持多 Guard + 双令牌模�全增强
 */
class JwtServiceProvider extends BaseService implements EnvSeedProvider
{

    use \wise\support\traits\RegistersMigrations;
    use ServiceTrait;

    /**
     * 声明需要播种到 .env 的密钥（安装时自动生成，重装不覆盖）
     *
     * 默认算法 HS256 → 主 Guard 与 Admin Guard 各需一个独立的 HMAC 共享密钥。
     * RSA 非对称密钥（JWT_PRIVATE_KEY/PUBLIC_KEY 等）为 RS256/ES256 的备选加载方式，
     * 仅在切换算法时需要，故不在此强制生成，避免写入无用密钥。
     */
    public static function envSeeds(): array
    {
        return [
            'JWT_SECRET' => [
                'type'      => 'secret',
                'generator' => 'random_bytes_32',
                'comment'   => 'wise-jwt 默认 Guard (HS256) 共享签名密钥',
            ],
            'JWT_ADMIN_SECRET' => [
                'type'      => 'secret',
                'generator' => 'random_bytes_32',
                'comment'   => 'wise-jwt 后台 Admin Guard 专用签名密钥',
            ],
        ];
    }

    public function register(): void
    {
        $this->mergeConfig('wise-jwt');

        $this->app->make(ConfigCheckCollector::class)->register(
            new JwtSecretCheck($this->app->config)
        );

        $this->app->bind(JwtGuardManager::class, function (App $app) {
            return new JwtGuardManager($app->config->get('wise-jwt', []));
        });

        $this->app->bind(Jwt::class, function (App $app) {
            return $app->make(JwtGuardManager::class)->defaultJwt();
        });

        $this->app->bind(SignerInterface::class, function (App $app) {
            $config = $app->config->get('wise-jwt', []);
            $alg = strtoupper($config['algorithm'] ?? 'HS256');
            return SignerFactory::create($alg, $config);
        });

        $this->app->bind(Validator::class, function (App $app) {
            return JwtGuardManager::buildValidatorFromConfig(
                $app->config->get('wise-jwt', [])
            );
        });

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

        $this->app->bind(TokenFingerprinter::class, function (App $app) {
            $config = $app->config->get('wise-jwt.fingerprint', []);
            return new TokenFingerprinter($config['level'] ?? TokenFingerprinter::LEVEL_MEDIUM);
        });

        $this->app->bind(RateLimiter::class, function (App $app) {
            $config = $app->config->get('wise-jwt.throttle', []);
            return new RateLimiter(
                (int) ($config['max_attempts'] ?? 5),
                (int) ($config['decay_seconds'] ?? 60),
                $config['prefix'] ?? 'jwt:throttle:',
                (string) ($config['store'] ?? '')
            );
        });

        $this->app->bind(middleware\JwtAuth::class, function (App $app) {
            return new middleware\JwtAuth(
                $app->make(JwtGuardManager::class),
                $app->config->get('wise-jwt', [])
            );
        });

        $this->commands([
            command\KeyGenerate::class,
            command\Decode::class,
            command\Revoke::class,
            command\BlacklistManage::class,
        ]);
    }

    /**
     * 启动服务
     */
    public function boot(): void
    {
        $this->registerMigrations();

        $warnedGuards = [];
        $warnedLimit  = 64;

        ExtPoint::register(ExtPoints::JWT_PROVIDER, 'wise-jwt', function (?string $guard = null) use (&$warnedGuards, $warnedLimit) {
            if ($guard === null) {
                return $this->app->make(Jwt::class);
            }

            $manager = $this->app->make(JwtGuardManager::class);

            if ($manager->hasGuard($guard)) {
                return $manager->guard($guard);
            }

            if (!isset($warnedGuards[$guard]) && count($warnedGuards) < $warnedLimit) {
                $warnedGuards[$guard] = true;
                ContextualLogger::warning(
                    '[JWT] 守卫名未在 wise-jwt.guards 中登记，已回退默认引擎（跨守卫令牌可能互认）',
                    [
                        'guard'      => $guard,
                        'fallback'   => $manager->getDefaultGuard(),
                        'configured' => array_keys((array) $this->app->config->get('wise-jwt.guards', [])),
                    ]
                );
            }

            return $this->app->make(Jwt::class);
        });
    }
}
