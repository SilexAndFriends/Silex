<?php

/*
 * This file is part of the Silex framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Silex\Tests\Provider\SecurityServiceProviderTest;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;

/**
 * This class is used to test "guard" authentication with the SecurityServiceProvider.
 */
class TokenAuthenticator extends AbstractAuthenticator
{
    public function getCredentials(Request $request)
    {
        if (!$token = $request->headers->get('X-AUTH-TOKEN')) {
            return false;
        }

        list($username, $secret) = explode(':', $token);

        return [
            'username' => $username,
            'secret' => $secret,
        ];
    }

    public function supports(Request $request): ?bool
    {
        return !empty($request->headers->get('X-AUTH-TOKEN'));
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        return $userProvider->loadUserByIdentifier($credentials['username']);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        // This is not a safe way of validating a password.
        return $user->getPassword() === $credentials['secret'];
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        if ($exception->getPrevious() instanceof AuthenticationException) {
            $exception = $exception->getPrevious();
        }
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ];

        return new JsonResponse($data, 403);
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = [
            'message' => 'Authentication Required',
        ];

        return new JsonResponse($data, 401);
    }

    public function supportsRememberMe()
    {
        return false;
    }

    public function authenticate(Request $request): Passport
    {
        // TODO: Implement authenticate() method.
    }
}
