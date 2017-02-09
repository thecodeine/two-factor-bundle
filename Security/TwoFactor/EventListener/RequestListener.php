<?php

namespace Scheb\TwoFactorBundle\Security\TwoFactor\EventListener;

use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Request;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationHandlerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextFactoryInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class RequestListener
{
    /**
     * @var AuthenticationContextFactoryInterface
     */
    private $authenticationContextFactory;

    /**
     * @var AuthenticationHandlerInterface
     */
    private $authHandler;

    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;

    /**
     * @var array
     */
    private $supportedTokens;

    /**
     * @var array
     */
    private $accessControl;

    /**
     * Construct a listener for login events.
     *
     * @param AuthenticationContextFactoryInterface $authenticationContextFactory
     * @param AuthenticationHandlerInterface        $authHandler
     * @param TokenStorageInterface                 $tokenStorage
     * @param array                                 $supportedTokens
     * @param array                                 $accessControl
     */
    public function __construct(
        AuthenticationContextFactoryInterface $authenticationContextFactory,
        AuthenticationHandlerInterface $authHandler,
        TokenStorageInterface $tokenStorage,
        array $supportedTokens,
        $accessControl
    ) {
        $this->authenticationContextFactory = $authenticationContextFactory;
        $this->authHandler = $authHandler;
        $this->tokenStorage = $tokenStorage;
        $this->supportedTokens = $supportedTokens;
        $this->accessControl = $accessControl;
    }

    /**
     * Listen for request events.
     *
     * @param GetResponseEvent $event
     */
    public function onCoreRequest(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        // Check access control
        if (!$this->isSecuredPath($request)) return;

        // Check if security token is supported
        $token = $this->tokenStorage->getToken();
        if (!$this->isTokenSupported($token)) {
            return;
        }

        // Forward to two-factor provider
        // Providers can create a response object
        $context = $this->authenticationContextFactory->create($request, $token);
        $response = $this->authHandler->requestAuthenticationCode($context);

        // Set the response (if there is one)
        if ($response instanceof Response) {
            $event->setResponse($response);
        }
    }

    /**
     * Check if the token class is supported.
     *
     * @param mixed $token
     *
     * @return bool
     */
    private function isTokenSupported($token)
    {
        if (null === $token) {
            return false;
        }

        $class = get_class($token);

        return in_array($class, $this->supportedTokens);
    }

    /**
     * Check if current path is secured by two-factor authentication
     *
     * @param Request $request
     *
     * @return bool
     */
    private function isSecuredPath(Request $request) {
        foreach($this->accessControl as $access) {
            $path = $access['path'];

            if (null !== $path && preg_match('{'.$path.'}', rawurldecode($request->getPathInfo()))) {
                return true;
            }
        }

        return false;
    }
}
