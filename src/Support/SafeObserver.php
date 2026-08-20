<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Support;

use SafeApple\SignIn\Contract\Observer;
use Throwable;

/** Prevents a logging or metrics outage from breaking authentication. */
final class SafeObserver implements Observer
{
    public function __construct(private readonly Observer $observer)
    {
    }

    public function record(string $event, array $context = []): void
    {
        try {
            $this->observer->record($event, $context);
        } catch (Throwable) {
        }
    }
}
