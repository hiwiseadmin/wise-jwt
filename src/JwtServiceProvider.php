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
 * wise-jwt 服务注册 — 支持多 Guard + 双令牌模式 + P1 安全增强
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

        // 注册配置检查项 → ConfigCheckCollector 统一管理和输出
        $this->app->make(ConfigCheckCollector::class)->register(
            new JwtSecretCheck($this->app->config)
        );

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

        // ── 绑定默认 Validator（委托给 JwtGuardManager 统一构建逻辑） ──
        $this->app->bind(Validator::class, function (App $app) {
            return JwtGuardManager::buildValidatorFromConfig(
                $app->config->get('wise-jwt', [])
            );
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
        $this->app->bind(middleware\JwtAuth::class, function (App $app) {
            return new middleware\JwtAuth(
                $app->make(JwtGuardManager::class),
                $app->config->get('wise-jwt', [])
            );
        });

        // 注册 CLI 命令（仅在真正执行 php think ... 时触发）
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

        // 注册 JWT 引擎到统一扩展点
        // JwtManager → ExtPoint('jwt.provider') → 此实现 → 容器中的 Jwt 实例
        //
        // 传入 guard 名时返回该守卫专属引擎（各自密钥 / issuer / audience），
        // 使 TokenGuard('admin') 这类已配置的守卫不会与默认守卫共用凭证规则。
        //
        // 未在 wise-jwt.guards 中登记的守卫名仍回退默认引擎（兼容「鉴权守卫名 ≠ JWT
        // 守卫名」的既有用法，例如宿主以 TokenGuard('api') 表达 API 鉴权入口，而令牌
        // 实际由默认引擎签发），但每个守卫名只告警一次：回退是静默的，配置疏漏时
        // 跨守卫令牌会互相通过，必须让问题可见。
        $warnedGuards = [];
        ExtPoint::register(ExtPoints::JWT_PROVIDER, 'wise-jwt', function (?string $guard = null) use (&$warnedGuards) {
            if ($guard === null) {
                return $this->app->make(Jwt::class);
            }

            $manager = $this->app->make(JwtGuardManager::class);

            if ($manager->hasGuard($guard)) {
                return $manager->guard($guard);
            }

            if (!isset($warnedGuards[$guard])) {
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
