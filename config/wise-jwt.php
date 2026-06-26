<?php
declare(strict_types=1);

return [
    // ── 默认算法与密钥 ──
    'default'     => 'app',
    'algorithm'   => env('JWT_ALGORITHM', 'HS256'),
    'secret'      => env('JWT_SECRET', ''),
    'private_key' => env('JWT_PRIVATE_KEY', ''),
    'public_key'  => env('JWT_PUBLIC_KEY', ''),

    // ── 签发参数 ──
    'issuer'      => env('JWT_ISSUER', 'wiseadmin'),
    'audience'    => env('JWT_AUDIENCE', ''),
    'ttl'         => (int) env('JWT_TTL', 7200),
    'refresh_ttl' => (int) env('JWT_REFRESH_TTL', 1800),

    // ── 时间容差（秒） ──
    'leeway'      => (int) env('JWT_LEEWAY', 0),

    // ── 黑名单 ──
    'blacklist' => [
        'enable'  => env('JWT_BLACKLIST_ENABLE', true),
        'driver'  => env('JWT_BLACKLIST_DRIVER', 'cache'),
        'prefix'  => env('JWT_BLACKLIST_PREFIX', 'jwt:blacklist:'),
        // DB 驱动专用表名
        'db_table' => env('JWT_BLACKLIST_DB_TABLE', 'jwt_blacklist'),
    ],

    // ── Refresh Token 双令牌模式 ──
    'refresh_token' => [
        // 是否启用双令牌模式（issuePair / refreshAccessToken）
        'enable'          => env('JWT_REFRESH_TOKEN_ENABLE', true),

        // Refresh Token 有效期（秒），默认 30 天
        'ttl'             => (int) env('JWT_REFRESH_TOKEN_TTL', 2592000),

        // Token 指纹绑定
        'fingerprint'     => env('JWT_REFRESH_TOKEN_FINGERPRINT', false),
    ],

    // ── P1: 设备指纹绑定 ──
    'fingerprint' => [
        // 是否启用设备指纹绑定（签发时写入 fph，解析时校验）
        'enable' => env('JWT_FINGERPRINT_ENABLE', false),

        // 安全强度：LOW（仅 UA）| MEDIUM（UA+IP）| HIGH（UA+IP+Lang+Encoding）
        'level'  => env('JWT_FINGERPRINT_LEVEL', 'MEDIUM'),

        // 严格模式：true=无指纹的 token 拒绝；false=仅校验有指纹的 token
        'strict' => env('JWT_FINGERPRINT_STRICT', false),
    ],

    // ── P1: 频率限制 ──
    'throttle' => [
        // 是否启用频率限制
        'enable'       => env('JWT_THROTTLE_ENABLE', false),

        // 最大尝试次数
        'max_attempts' => (int) env('JWT_THROTTLE_MAX_ATTEMPTS', 5),

        // 冷却时间（秒）
        'decay_seconds' => (int) env('JWT_THROTTLE_DECAY_SECONDS', 60),

        // 限流键类型：ip | route | ip_route
        'key_type'     => env('JWT_THROTTLE_KEY_TYPE', 'ip'),

        // 缓存前缀
        'prefix'       => env('JWT_THROTTLE_PREFIX', 'jwt:throttle:'),
    ],

    // ── P1: 全局令牌失效（Token Version） ──
    'global_revoke' => [
        // 是否启用全局令牌失效
        'enable' => env('JWT_GLOBAL_REVOKE_ENABLE', false),
    ],

    // ── P1: 密钥轮换（多密钥配置） ──
    // 主密钥通过顶层 secret/private_key/public_key 配置
    // keys 数组用于密钥轮换，格式：
    // 'keys' => [
    //     ['kid' => '2026-01', 'secret' => '...', 'active' => true],
    //     ['kid' => '2025-07', 'secret' => '...', 'active' => false],
    // ],
    // 注意：env() 只能返回字符串，密钥轮换数组请通过 PHP 配置文件（如 config/wise-jwt.php）直接定义，
    // 或通过 env('JWT_KEYS') 返回 JSON 字符串后自行解析
    'keys' => [],

    // ── Token 提取 ──
    'token' => [
        'extractors'  => ['bearer', 'cookie', 'query'],
        'header_name' => 'Authorization',
        'cookie_name' => 'wise_token',
        'query_name'  => 'token',
    ],

    // ── 多 Guard 支持 ──
    'guards' => [
        'app' => [
            'algorithm'   => env('JWT_ALGORITHM', 'HS256'),
            'secret'      => env('JWT_SECRET', ''),
            'private_key' => env('JWT_PRIVATE_KEY', ''),
            'public_key'  => env('JWT_PUBLIC_KEY', ''),
            'issuer'      => 'wiseadmin-app',
            'audience'    => env('JWT_AUDIENCE', ''),
            'ttl'         => (int) env('JWT_TTL', 7200),
            'refresh_ttl' => (int) env('JWT_REFRESH_TTL', 1800),
            'refresh_token_ttl' => (int) env('JWT_REFRESH_TOKEN_TTL', 2592000),
            'blacklist'   => [
                'enable'  => true,
                'driver'  => env('JWT_BLACKLIST_DRIVER', 'cache'),
                'prefix'  => env('JWT_BLACKLIST_PREFIX', 'jwt:blacklist:'),
                'db_table' => env('JWT_BLACKLIST_DB_TABLE', 'jwt_blacklist'),
            ],
        ],
        'admin' => [
            'algorithm'   => env('JWT_ADMIN_ALGORITHM', 'HS256'),
            'secret'      => env('JWT_ADMIN_SECRET', ''),
            'private_key' => env('JWT_ADMIN_PRIVATE_KEY', ''),
            'public_key'  => env('JWT_ADMIN_PUBLIC_KEY', ''),
            'issuer'      => 'wiseadmin-admin',
            'audience'    => env('JWT_ADMIN_AUDIENCE', ''),
            'ttl'         => (int) env('JWT_ADMIN_TTL', 3600),
            'refresh_ttl' => (int) env('JWT_ADMIN_REFRESH_TTL', 900),
            'refresh_token_ttl' => (int) env('JWT_ADMIN_REFRESH_TOKEN_TTL', 1209600),
            'blacklist'   => [
                'enable'  => true,
                'driver'  => env('JWT_BLACKLIST_DRIVER', 'cache'),
                'prefix'  => env('JWT_ADMIN_BLACKLIST_PREFIX', 'jwt:admin:blacklist:'),
                'db_table' => env('JWT_BLACKLIST_DB_TABLE', 'jwt_blacklist'),
            ],
        ],
    ],

    // ── 自动续签 ──
    'auto_refresh' => true,

    // ── 校验规则 ──
    'validation' => [
        'check_expiration' => true,
        'check_not_before' => true,
        'check_issued_at'  => true,
        'check_issuer'     => true,
        'check_audience'   => false,
    ],
];
