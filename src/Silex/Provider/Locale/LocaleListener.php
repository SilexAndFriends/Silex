<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider\Locale;

use Pimple\Container;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\FinishRequestEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\RequestContext;

/**
 * Initializes the locale based on the current request.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 * @author Jérôme Tamarelle <jerome@tamarelle.net>
 */
class LocaleListener implements EventSubscriberInterface
{
    private Container $app;
    private string $defaultLocale;
    private RequestStack $requestStack;
    private ?RequestContext $requestContext;

    public function __construct(Container $app, ?string $defaultLocale, RequestStack $requestStack, RequestContext $requestContext = null)
    {
        $this->app = $app;
        $this->defaultLocale = $defaultLocale ?: 'en';
        $this->requestStack = $requestStack;
        $this->requestContext = $requestContext;
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        $request = $event->getRequest();
        $request->setDefaultLocale($this->defaultLocale);

        $this->setLocale($request);
        $this->setRouterContext($request);

        $this->app['locale'] = $request->getLocale();
    }

    public function onKernelFinishRequest(FinishRequestEvent $event)
    {
        if (null !== $parentRequest = $this->requestStack->getParentRequest()) {
            $this->setRouterContext($parentRequest);
        }
    }

    private function setLocale(Request $request): void
    {
        if ($locale = $request->attributes->get('_locale')) {
            $request->setLocale($locale);
        }
    }

    private function setRouterContext(Request $request): void
    {
        if (null !== $this->requestContext) {
            $this->requestContext->setParameter('_locale', $request->getLocale());
        }
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // must be registered after the Router to have access to the _locale
            KernelEvents::REQUEST => [['onKernelRequest', 16]],
            KernelEvents::FINISH_REQUEST => [['onKernelFinishRequest', 0]],
        ];
    }
}
