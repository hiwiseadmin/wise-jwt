<?php
declare(strict_types=1);


require_once __DIR__ . '/stubs/think/facade/Event.php';
require_once __DIR__ . '/stubs/think/facade/Cache.php';
require_once __DIR__ . '/stubs/think/facade/Log.php';

$projectAutoload = __DIR__ . '/../../../../vendor/autoload.php';
if (file_exists($projectAutoload)) {
    $prevErrorReporting = error_reporting(E_ALL & ~E_WARNING);
    try {
        require_once $projectAutoload;
    } catch (\Throwable $e) {
    }
    error_reporting($prevErrorReporting);
}

spl_autoload_register(function (string $class): void {
    $prefix = 'wise\\jwt\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relativeClass = substr($class, strlen($prefix));

    if (str_starts_with($relativeClass, 'tests\\')) {
        $file = __DIR__ . '/' . str_replace('\\', '/', $relativeClass) . '.php';
    } else {
        $file = __DIR__ . '/../src/' . str_replace('\\', '/', $relativeClass) . '.php';
    }

    if (file_exists($file)) {
        require $file;
    }
});

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
