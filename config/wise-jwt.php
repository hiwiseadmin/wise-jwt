<?php
declare(strict_types=1);

/**
 * Wise-JWT 配置文件
 *
 */

return [
    // ── 默认 Guard 与密钥 ──
    'default'     => 'app',
    'algorithm'   => 'HS256',

    // HMAC 密钥（HS256/HS384/HS512）
    // 优先级：secret > secret_base64 > secret_file
    'secret'      => env('JWT_SECRET', ''),
    'secret_base64' => env('JWT_SECRET_BASE64', ''),
    'secret_file'   => env('JWT_SECRET_FILE', ''),

    // RSA/EC/EdDSA 非对称密钥（仅在使用非对称算法时需要）
    // 优先级：直接值 > _base64 > _file
    'private_key'      => env('JWT_PRIVATE_KEY', ''),
    'private_key_base64' => env('JWT_PRIVATE_KEY_BASE64', ''),
    'private_key_file'   => env('JWT_PRIVATE_KEY_FILE', ''),
    'public_key'       => env('JWT_PUBLIC_KEY', ''),
    'public_key_base64'  => env('JWT_PUBLIC_KEY_BASE64', ''),
    'public_key_file'    => env('JWT_PUBLIC_KEY_FILE', ''),

    // ── 签发参数 ──
    'issuer'      => 'wiseadmin',
    'audience'    => '',
    'ttl'         => 7200,
    'refresh_ttl' => 1800,

    // ── 时间容差（秒） ──
    'leeway'      => 0,

    // ── 黑名单 ──
    'blacklist' => [
        'enable'   => true,
        'driver'   => 'cache',
        'prefix'   => 'jwt:blacklist:',
        'db_table' => 'jwt_blacklist',
    ],

    // ── Refresh Token 双令牌模式 ──
    'refresh_token' => [
        'enable'      => true,
        'ttl'         => 2592000,  // 默认 30 天
        'fingerprint' => false,
    ],

    // ── P1: 设备指纹绑定 ──
    'fingerprint' => [
        'enable' => false,
        'level'  => 'MEDIUM',  // LOW(仅UA) | MEDIUM(UA+IP) | HIGH(UA+IP+Lang+Encoding)
        'strict' => false,
    ],

    // ── P1: 频率限制 ──
    'throttle' => [
        'enable'       => false,
        'max_attempts' => 5,
        'decay_seconds' => 60,
        'key_type'     => 'ip',
        'prefix'       => 'jwt:throttle:',
    ],

    // ── P1: 全局令牌失效 ──
    'global_revoke' => [
        'enable' => false,
    ],

    // ── P1: 令牌版本号持久化（防缓存清除导致令牌重新有效） ──
    'version_persistence' => [
        // 是否启用文件持久化（强烈建议开启）
        'enable'    => true,
        // 持久化文件存储目录，留空使用默认 runtime/wise-jwt/version/
        // 建议配置到项目 data 目录，确保不随 cache:clear 丢失
        'file_path' => '',
    ],

    // ── P1: 密钥轮换 ──
    'keys' => [],

    // ── Token 提取 ──
    // 默认仅 Bearer：query 会让令牌进入 URL/日志/Referer，cookie 需配套 CSRF 防护，
    // 二者应由使用方按场景显式开启（路由级参数或此处追加）。
    'token' => [
        'extractors'  => ['bearer'],
        'header_name' => 'Authorization',
        'cookie_name' => 'wise_token',
        'query_name'  => 'token',
    ],

    // ── 多 Guard 支持 ──
    'guards' => [
        'app' => [
            'algorithm'         => 'HS256',
            // 留空则自动继承顶层 secret（JwtGuardManager 合并逻辑）
            'secret'            => '',
            'private_key'       => '',
            'public_key'        => '',
            'issuer'            => 'wiseadmin-app',
            'audience'          => '',
            'ttl'               => 7200,
            'refresh_ttl'       => 1800,
            'refresh_token_ttl' => 2592000,
            'blacklist'         => [
                'enable'   => true,
                'driver'   => 'cache',
                'prefix'   => 'jwt:blacklist:',
                'db_table' => 'jwt_blacklist',
            ],
        ],
        'admin' => [
            'algorithm'         => 'HS256',
            // 管理后台独立 HMAC 密钥，通过 JWT_ADMIN_SECRET 环境变量配置
            'secret'            => env('JWT_ADMIN_SECRET', ''),
            'private_key'       => '',
            'public_key'        => '',
            'issuer'            => 'wiseadmin-admin',
            'audience'          => '',
            'ttl'               => 3600,
            'refresh_ttl'       => 900,
            'refresh_token_ttl' => 1209600,
            'blacklist'         => [
                'enable'   => true,
                'driver'   => 'cache',
                'prefix'   => 'jwt:admin:blacklist:',
                'db_table' => 'jwt_blacklist',
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
