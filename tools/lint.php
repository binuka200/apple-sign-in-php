<?php

declare(strict_types=1);

$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../src'));

foreach ($files as $file) {
    if (!$file instanceof SplFileInfo || $file->getExtension() !== 'php') {
        continue;
    }

    passthru(
        escapeshellarg(PHP_BINARY).' -n -l '.escapeshellarg($file->getPathname()),
        $exitCode,
    );
    if ($exitCode !== 0) {
        exit($exitCode);
    }
}
