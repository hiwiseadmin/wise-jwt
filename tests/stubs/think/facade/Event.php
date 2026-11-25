<?php
declare(strict_types=1);

namespace think\facade;

/**
 * Event 门面桩 — 测试用
 */
class Event
{
    private static array $listeners = [];

    public static function trigger(mixed $event): void
    {
    }

    public static function listen(string $event, callable $listener): void
    {
        self::$listeners[$event][] = $listener;
    }

    public static function hasListener(string $event): bool
    {
        return isset(self::$listeners[$event]);
    }
}
