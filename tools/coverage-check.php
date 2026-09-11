<?php

declare(strict_types=1);

$cloverPath = $argv[1] ?? __DIR__.'/../.phpunit.cache/clover.xml';
$minimum = (float) ($argv[2] ?? 0);

if (!is_file($cloverPath)) {
    fwrite(STDERR, "Coverage report not found at {$cloverPath}.\n");
    exit(1);
}

$clover = @simplexml_load_file($cloverPath);
if ($clover === false) {
    fwrite(STDERR, "Coverage report at {$cloverPath} is not readable XML.\n");
    exit(1);
}

$metrics = $clover->project->metrics ?? null;
if ($metrics === null) {
    fwrite(STDERR, "Coverage report at {$cloverPath} has no project metrics.\n");
    exit(1);
}

$statements = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];
if ($statements === 0) {
    fwrite(STDERR, "Coverage report contains no executable statements.\n");
    exit(1);
}

$percentage = $covered / $statements * 100;

$perFile = [];
foreach ($clover->xpath('//file') ?: [] as $file) {
    $fileStatements = (int) $file->metrics['statements'];
    if ($fileStatements === 0) {
        continue;
    }

    $perFile[basename((string) $file['name'])] = (int) $file->metrics['coveredstatements'] / $fileStatements * 100;
}

asort($perFile);

printf("Line coverage: %.2f%% (%d/%d statements)\n", $percentage, $covered, $statements);
printf("Lowest covered files:\n");
foreach (array_slice($perFile, 0, 5, true) as $name => $filePercentage) {
    printf("  %6.2f%%  %s\n", $filePercentage, $name);
}

if ($minimum > 0 && $percentage + 0.005 < $minimum) {
    fwrite(STDERR, sprintf("Line coverage %.2f%% is below the required %.2f%%.\n", $percentage, $minimum));
    exit(1);
}

exit(0);
