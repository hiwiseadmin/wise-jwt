<?php
declare(strict_types=1);

namespace think\facade;

/**
 * Cache 门面桩 — 基于内存数组的简易缓存
 */
class Cache
{
    private static array $store = [];
    private static array $expires = [];

    public static function set(string $key, mixed $value, mixed $ttl = null): bool
    {
        self::$store[$key] = $value;

        if ($ttl !== null && $ttl > 0) {
            self::$expires[$key] = time() + (int) $ttl;
        } else {
            unset(self::$expires[$key]);
        }

        return true;
    }

    /**
     * 仅当键不存在时写入（SETNX 语义）
     */
    public static function add(string $key, mixed $value, mixed $ttl = null): bool
    {
        if (self::has($key)) {
            return false;
        }

        return self::set($key, $value, $ttl);
    }

    public static function has(string $key): bool
    {
        if (!isset(self::$store[$key])) {
            return false;
        }

        // 检查是否过期
        if (isset(self::$expires[$key]) && time() > self::$expires[$key]) {
            unset(self::$store[$key], self::$expires[$key]);
            return false;
        }

        return true;
    }

    public static function delete(string $key): bool
    {
        unset(self::$store[$key], self::$expires[$key]);
        return true;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        if (!self::has($key)) {
            return $default;
        }
        return self::$store[$key];
    }

    public static function clear(): void
    {
        self::$store = [];
        self::$expires = [];
    }
}
