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
$projectAutoload = __DIR__ . '/../../../../vendor/autoload.php';
// Note: not loading project autoloader to avoid path repository resolution failures.
// All required classes are handled by stubs + manual PSR-4 autoloader below.

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
