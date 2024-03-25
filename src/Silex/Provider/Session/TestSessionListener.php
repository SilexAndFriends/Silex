<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider\Session;

use Pimple\Container;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\EventListener\TestSessionListener as BaseTestSessionListener;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Simulates sessions for testing purpose.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class TestSessionListener implements EventSubscriberInterface
{
    private Container $app;
    private BaseTestSessionListener $testSessionListener;

    public function __construct(Container $app)
    {
        $this->app = $app;
        $this->testSessionListener = new BaseTestSessionListener(new \Pimple\Psr11\Container($app));
    }

    protected function getSession(): ?SessionInterface
    {
        return $this->app['session'] ?? null;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $this->testSessionListener->onKernelRequest($event);
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        $this->testSessionListener->onKernelResponse($event);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onKernelRequest', 192],
            KernelEvents::RESPONSE => ['onKernelResponse', -128],
        ];
    }


}
