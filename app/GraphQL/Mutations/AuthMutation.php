<?php

namespace App\GraphQL\Mutations;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Config\Repository as Config; 
use Nuwave\Lighthouse\Exceptions\AuthenticationException; 

final class AuthMutation
{
    protected AuthManager $authManager;
    
    public function __construct(AuthManager $authManager, Config $config)
    {
        $this->authManager = $authManager; 
    }
    /**
     * @param  null  $_
     * @param  array{}  $args
     */
    public function login($_, array $args)
    {
        // TODO implement the resolver
        $userProvider = $this->authManager->createUserProvider('users');
        $user = $userProvider->retrieveByCredentials([
            'email'    => $args['email'],
            'password' => $args['password'],
        ]);

        if (!$user || !$userProvider->validateCredentials($user, $args)) {
            throw new AuthenticationException('The provided credentials are incorrect.');
        }

        if ($user instanceof MustVerifyEmail && !$user->hasVerifiedEmail()) {
            throw new AuthenticationException('Your email address is not verified.');
        }
        
        return [
            'token' => $user()->createToken('default')->plainTextToken,
        ];
    }
    public function logout($_, array $args)
    {
        // TODO implement the resolver
        $userProvider = $this->authManager->createUserProvider('users');
        $user = $userProvider->retrieveByCredentials([
            'email'    => $args['email'],
            'password' => $args['password'],
        ]);

        if (!$user || !$userProvider->validateCredentials($user, $args)) {
            throw new AuthenticationException('The provided credentials are incorrect.');
        }

        if ($user instanceof MustVerifyEmail && !$user->hasVerifiedEmail()) {
            throw new AuthenticationException('Your email address is not verified.');
        }
        
        return [
            'token' => $user()->createToken('default')->plainTextToken,
        ];
    }
}
