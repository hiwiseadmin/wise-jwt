<?php
declare(strict_types=1);

if (!function_exists('wise_jwt')) {
    /**
     * 获取 JWT 实例
     *
     * @param string|null $guard Guard 名称，null 表示默认（app）
     * @return \wise\jwt\Jwt
     *
     * 用法：
     * $jwt = wise_jwt();              // 默认 guard (app)
     * $token = wise_jwt()->issue('user-1');
     *
     * $adminJwt = wise_jwt('admin');  // admin guard
     * $token = $adminJwt->issue('admin-1');
     */
    function wise_jwt(?string $guard = null): \wise\jwt\Jwt
    {
        if (!function_exists('app')) {
            throw new \RuntimeException('wise_jwt() helper requires ThinkPHP framework environment');
        }
        /** @var \wise\jwt\JwtGuardManager $manager */
        $manager = app(\wise\jwt\JwtGuardManager::class);
        return $manager->guard($guard);
    }
}
