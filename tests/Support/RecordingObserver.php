<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Tests\Support;

use SafeApple\SignIn\Contract\Observer;

final class RecordingObserver implements Observer
{
    /** @var list<array{event: string, context: array<string, bool|int|float|string|null>}> */
    public array $records = [];

    public function record(string $event, array $context = []): void
    {
        $this->records[] = ['event' => $event, 'context' => $context];
    }
}
