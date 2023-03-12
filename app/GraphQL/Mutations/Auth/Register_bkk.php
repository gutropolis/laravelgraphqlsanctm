<?php

namespace App\GraphQL\Mutations\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Auth\AuthManager;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr; 
final class Register
{
    protected AuthManager $authManager;
    protected Config $config;
    protected Hasher $hash;
    protected MustVerifyEmail $emailVerificationService;

    public function __construct(
        AuthManager $authManager,
        Config $config,
        Hasher $hash,
        MustVerifyEmail $emailVerificationService
    ) {
        $this->authManager              = $authManager;
        $this->config                   = $config;
        $this->hash                     = $hash;
        $this->emailVerificationService = $emailVerificationService;
    }
    /**
     * @param  null  $_
     * @param  array{}  $args
     */
     
     public function __invoke($_, array $args): array
    {
        /** @var EloquentUserProvider $userProvider */ 
        $userProvider = $this->authManager->createUserProvider('users');
        $user = $this->saveUser(
            $userProvider->createModel(),
            $this->getPropertiesFromArgs($args),
        );
        Log::info('USER INFO', ['coyntext' => $user]);
        
        if ($user instanceof MustVerifyEmail) { 
            $user->sendEmailVerificationNotification();

            return [
                'token'  => null,
                'status' => 'MUST_VERIFY_EMAIL',
            ];
        } 
        return [
            'token'  => $user->createToken('default')->plainTextToken,
            'status' => 'SUCCESS',
        ];
    }

    /**
     * @param Model $user
     * @param array<string, mixed> $attributes
     * @return Model
     */
    protected function saveUser(Model $user, array $attributes): Model
    {
        $user
            ->fill($attributes)
            ->save();

        return $user;
    }

    /**
     * @param array<string, mixed> $args
     * @return array<string, string>
     */
    protected function getPropertiesFromArgs(array $args): array
    {
        $properties = Arr::except($args, [
            'directive',
            'password_confirmation',
            'verification_url',
        ]);

        $properties['password'] = $this->hash->make($properties['password']);

        return $properties;
    }

    protected function getAuthManager(): AuthManager
    {
        return $this->authManager;
    }

    protected function getConfig(): Config
    {
        return $this->config;
    }
}
