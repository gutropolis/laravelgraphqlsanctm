<?php

namespace App\GraphQL\Mutations\Auth; 
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Translation\Translator; 
use App\Exceptions\GraphQLValidationException;
use GraphQL\Type\Definition\ResolveInfo;
use Illuminate\Contracts\Hashing\Hasher;
use RuntimeException; 
final class UpdatePassword
{
    protected AuthFactory $authFactory;
    protected Translator $translator;
    protected AuthManager $authManager;
    protected Hasher $hasher;
    protected ResolveInfo $resolveInfo;
    public function __construct(AuthManager $authManager,AuthFactory $authFactory, Translator $translator, Hasher $hasher,)
    {
        $this->authManager = $authManager;
        $this->authFactory = $authFactory;
        $this->translator  = $translator;
        $this->hasher      = $hasher;
    }

    /**
     * @param  null  $_
     * @param  array{}  $args
     */
    public function __invoke($_, array $args)
    {
        $user = $this->getAuthFactory()
        ->guard('sanctum')
        ->user();

        if (! $user) {
            throw new RuntimeException('Unable to detect current user.');
        }
 
      
        
        $this->currentPasswordMustBeTheSame($user, $args['current_password']);
        $this->newPasswordMustBeDifferent($user, $args['password']);

        $user()->password = $this->hasher->make($args['password']); 
        $user()->save(); 
       

        return [
            'status' => 'PASSWORD_UPDATED',
        ];
    }
/**
     * @param Authenticatable $user
     * @param string $currentPassword
     * @throws GraphQLValidationException
     */
    protected function currentPasswordMustBeTheSame(Authenticatable $user, string $currentPassword): void
    {
        if (! $this->hasher->check($currentPassword, $user->getAuthPassword())) {
            /** @var string $message */
            $message = $this->translator->get('validation.same', [
                'attribute' => 'current_password',
                'other'     => 'user password',
            ]);

            throw new GraphQLValidationException($message, 'current_password', $this->resolveInfo);
        }
    }

    /**
     * @param Authenticatable $user
     * @param string $newPassword
     * @throws GraphQLValidationException
     */
    protected function newPasswordMustBeDifferent(Authenticatable $user, string $newPassword): void
    {
        if ($this->hasher->check($newPassword, $user->getAuthPassword())) {
            /** @var string $message */
            $message = $this->translator->get('validation.different', [
                'attribute' => 'password',
                'other'     => 'user password',
            ]);

            throw new GraphQLValidationException($message, 'password', $this->resolveInfo);
        }
    }

    protected function getAuthFactory(): AuthFactory
    {
        return $this->authFactory;
    }

}