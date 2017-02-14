<?php

namespace Scheb\TwoFactorBundle\Twig;

use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticator;

class TwigExtension extends \Twig_Extension
{

    public function __construct(GoogleAuthenticator $googleAuthenticator)
    {
        $this->googleAuthenticator = $googleAuthenticator;
    }

    /**
     * @return array
     */
    public function getFilters()
    {
        return [
            new \Twig_SimpleFilter('generate_core_url', [$this, 'generateCode']),
        ];
    }

    public function generateCode($user)
    {
        return $this->googleAuthenticator->getUrl($user);
    }

    public function getName()
    {
        return 'app_extension';
    }
}
