<?php

namespace App\GraphQL\Mutations\Auth;
use Exception;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Translation\Translator;
use Laravel\Sanctum\Contracts\HasApiTokens;
use Laravel\Sanctum\PersonalAccessToken;
use RuntimeException;

final class Logout
{


    protected AuthFactory $authFactory;
    protected Translator $translator;
    protected AuthManager $authManager;

    public function __construct(AuthManager $authManager,AuthFactory $authFactory, Translator $translator)
    {
        $this->authManager = $authManager;
        $this->authFactory = $authFactory;
        $this->translator  = $translator;
    }

    /**
     * @param  null  $_
     * @param  array{}  $args
     */
    public function __invoke($_, array $args)
    {
        $user = $this->getAuthFactory()->guard('sanctum')->user();

        if (! $user) {
            throw new RuntimeException('Unable to detect current user.');
        }
  
       // if (!$user instanceof HasApiTokens) {
          //  throw new RuntimeException('No instance of HasApiTokens');
        //}

        /** @var PersonalAccessToken $personalAccessToken */
        $personalAccessToken = $user->currentAccessToken();
        $personalAccessToken->delete();

        /** @var string $message */
        $message = $this->translator->get('Your session has been terminated');

        return [
            'status'  => 'TOKEN_REVOKED',
            'message' => $message,
        ];
    }

    protected function getAuthFactory(): AuthFactory
    {
        return $this->authFactory;
    }

}
