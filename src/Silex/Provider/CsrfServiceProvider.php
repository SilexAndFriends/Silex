<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Silex\Provider;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Csrf\CsrfTokenManager;
use Symfony\Component\Security\Csrf\TokenGenerator\UriSafeTokenGenerator;
use Symfony\Component\Security\Csrf\TokenStorage\SessionTokenStorage;
use Symfony\Component\Security\Csrf\TokenStorage\NativeSessionTokenStorage;

/**
 * Symfony CSRF Security component Provider.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class CsrfServiceProvider implements ServiceProviderInterface
{
    public function register(Container $app)
    {
        $app['csrf.token_manager'] = function ($app) {
            return new CsrfTokenManager($app['csrf.token_generator'], $app['csrf.token_storage']);
        };

        $app['csrf.token_storage'] = function ($app) {
            if (isset($app['session'])) {
                // Have tried using the already built in `request_stack`
                // but its session sometimes does not match `session`
                $request = new Request();
                $request->setSession($app['session']);

                $requestStack = new RequestStack();
                $requestStack->push($request);
                return new SessionTokenStorage($requestStack, $app['csrf.session_namespace']);
            }

            return new NativeSessionTokenStorage($app['csrf.session_namespace']);
        };

        $app['csrf.token_generator'] = function ($app) {
            return new UriSafeTokenGenerator();
        };

        $app['csrf.session_namespace'] = '_csrf';
    }
}
