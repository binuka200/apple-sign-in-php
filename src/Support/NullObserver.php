<?php

declare(strict_types=1);

namespace SafeApple\SignIn\Support;

use SafeApple\SignIn\Contract\Observer;

final class NullObserver implements Observer
{
    public function record(string $event, array $context = []): void
    {
    }
}
