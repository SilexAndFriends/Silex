<?php

use Rector\Config\RectorConfig;
use Rector\Symfony\Set\SymfonySetList;
use Rector\TypeDeclaration\Rector\Property\TypedPropertyFromStrictConstructorRector;

return RectorConfig::configure()
    ->withSymfonyContainerPhp(__DIR__ . '/tests/symfony-container.php')
    ->withSets([
        SymfonySetList::SYMFONY_64
    ])
    ->withPaths([
        __DIR__ . '/src',
    ]);
