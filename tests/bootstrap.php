<?php
declare(strict_types=1);

// Bootstrap for wise-jwt tests

// 1. Pre-load ThinkPHP facade stubs BEFORE project autoloader
//    This ensures our stubs take precedence over Composer's classmap
require_once __DIR__ . '/stubs/think/facade/Event.php';
require_once __DIR__ . '/stubs/think/facade/Cache.php';
require_once __DIR__ . '/stubs/think/facade/Log.php';

// 2. Load project autoloader if available and resolvable
//    Skip if path repository references can't resolve (e.g., wise-agent)
//
//    注意顺序：stub 已在上方 require_once，类一旦定义，Composer 自动加载器
//    便不会再介入，因此 stub 优先于 vendor 中的真实门面。
//    加载 vendor/autoload.php 是为了让 wise\support 等依赖类可被自动加载
//    （不依赖 phpunit 入口恰好已加载过 autoloader 这一隐式前提）。
$projectAutoload = __DIR__ . '/../../../../vendor/autoload.php';
if (file_exists($projectAutoload)) {
    $prevErrorReporting = error_reporting(E_ALL & ~E_WARNING);
    try {
        require_once $projectAutoload;
    } catch (\Throwable $e) {
        // 路径仓库解析失败时回退到下方手动 PSR-4
    }
    error_reporting($prevErrorReporting);
}

// 3. Manual PSR-4 autoloader for wise-jwt source and test classes
spl_autoload_register(function (string $class): void {
    $prefix = 'wise\\jwt\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));

    // Test classes: wise\jwt\tests\* -> tests/ directory
    if (str_starts_with($relativeClass, 'tests\\')) {
        $file = __DIR__ . '/' . str_replace('\\', '/', $relativeClass) . '.php';
    } else {
        // Source classes: wise\jwt\* -> src/ directory
        $file = __DIR__ . '/../src/' . str_replace('\\', '/', $relativeClass) . '.php';
    }

    if (file_exists($file)) {
        require $file;
    }
});

// 4. 单仓开发布局兜底加载 wise-support
//    宿主 vendor 可能尚未安装 wise-support（path 仓库未 make 时），
//    此时所有异常类都会因 WiseException 缺失而报错，测试无法覆盖异常分支。
spl_autoload_register(function (string $class): void {
    $prefix = 'wise\\support\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $file = __DIR__ . '/../../wise-support/src/'
        . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});
