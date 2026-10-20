<?php
declare(strict_types=1);

namespace think\facade;

/**
 * Log 门面桩 — 测试用
 */
class Log
{
    /** @var array<int, array{level: string, message: string, context: array}> */
    private static array $records = [];

    private static bool $silent = true;

    public static function record(string $message, string $level = 'info', array $context = []): void
    {
        self::$records[] = ['level' => $level, 'message' => $message, 'context' => $context];
    }

    public static function info(string $message, array $context = []): void
    {
        self::record($message, 'info', $context);
    }

    public static function warning(string $message, array $context = []): void
    {
        self::record($message, 'warning', $context);
    }

    public static function error(string $message, array $context = []): void
    {
        self::record($message, 'error', $context);
    }

    /**
     * 获取所有日志记录
     * @return array<int, array{level: string, message: string, context: array}>
     */
    public static function getRecords(): array
    {
        return self::$records;
    }

    /**
     * 按级别获取日志记录
     * @return array<int, array{level: string, message: string, context: array}>
     */
    public static function getRecordsByLevel(string $level): array
    {
        return array_filter(self::$records, fn($r) => $r['level'] === $level);
    }

    /**
     * 检查是否包含特定消息
     */
    public static function hasRecord(string $partial): bool
    {
        foreach (self::$records as $r) {
            if (str_contains($r['message'], $partial)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 清除所有日志记录
     */
    public static function clear(): void
    {
        self::$records = [];
    }
}
