<?php

namespace App\GraphQL\Mutations\Auth;
use Illuminate\Support\Facades\Log;
use Exception;
use Illuminate\Auth\AuthManager;
use Carbon\Carbon; 
use \Illuminate\Validation\ValidationException;
use Illuminate\Contracts\Validation\Factory as ValidationFactory;
use GraphQL\Type\Definition\ResolveInfo;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Auth\MustVerifyEmail; 
use Nuwave\Lighthouse\Exceptions\AuthenticationException;    
use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;
use RuntimeException; 

final class VerifyEmail
{
    protected AuthManager $authManager;
    protected Config $config;
    protected Hasher $hash;
 
    protected ValidationFactory $validationFactory;
    
    public function __construct(
        AuthManager $authManager,
        Config $config,
        ValidationFactory $validationFactory,
        
    ) {
        $this->authManager              = $authManager;
        $this->config                   = $config;
        $this->validationFactory        = $validationFactory; 
    }

    /**
     * @param mixed $_
     * @param array<string, string|int> $args
     * @param GraphQLContext $context
     * @param ResolveInfo $resolveInfo
     * @return array<string, string>
     * @throws Exception
     */
    public function __invoke($_, array $args,  GraphQLContext $context, ResolveInfo $resolveInfo): array{
          
    
        // TODO implement the resolver
        $userProvider = $this->authManager->createUserProvider('users');
        
        $user = $userProvider->retrieveById($args['id']);
        Log::info('USER INFO', ['coyntext' =>  $user]);
        if (!$user) {
            throw new AuthenticationException('You must login to access this page.');
        }
        Log::info('USER INFO33', ['coyntext' =>  $user]);
        if (! $user instanceof MustVerifyEmail) {
            throw new RuntimeException('User must implement "' . MustVerifyEmail::class . '".');
        } 
        Log::info('USER INF3311', ['coyntext' =>  $user]);
        if (!hash_equals((string) $args['hash'], sha1($user->getEmailForVerification()))) {
            throw new AuthenticationException('You must login to access this page.'); 
        }
        
        Log::info('USER INF555', ['coyntext' =>  $user]);


        if ($this->config->get('lighthouse.use_signed_email_verification_url') === true) {
            
            $this->validateRequiredSignedArguments($args, implode('.', $resolveInfo->path));

            $this->verifySigned(
                $user,
                (string) $args['hash'],
                (int) $args['expires'],
                (string) $args['signature'],
            );
        } else {
            $this->verify( $user, (string) $args['hash']);
        }


        if (! $user()->hasVerifiedEmail()) {
            $user()->markEmailAsVerified(); 
        } 

        return [
            'status' => 'VERIFIED',
        ];
    }

    /**
     * @param array<string, string|int> $args
     * @param string                    $path
     * @throws ValidationException
     */
    protected function validateRequiredSignedArguments(array $args, string $path): void
    {
        $validator = $this->validationFactory->make($args, [
            'expires'   => ['required'],
            'signature' => ['required'],
        ]);

        if ($validator->fails()) {
            
            throw new ValidationException("Validation failed for the field [$path].", $validator);
        }
    }

    protected function getAuthManager(): AuthManager
    {
        return $this->authManager;
    }

    protected function getConfig(): Config
    {
        return $this->config;
    }

     /**
     * @param MustVerifyEmail $user
     * @param string          $hash
     * @throws AuthenticationException
     */
    public function verify(MustVerifyEmail $user, string $hash): void
    {
        if (! hash_equals($hash, $this->createHash($user))) {
            throw new AuthenticationException('The provided input is incorrect.');
        }
    }
    protected function createHash(MustVerifyEmail $user): string
    {
        return sha1($user->getEmailForVerification());
    }
     /**
     * @param MustVerifyEmail $user
     * @param string          $hash
     * @param int             $expires
     * @param string          $signature
     * @throws AuthenticationException
     */
    public function verifySigned(MustVerifyEmail $user, string $hash, int $expires, string $signature): void
    {
        $this->verify($user, $hash);

        if ($expires < Carbon::now()->getTimestamp()) {
            throw new AuthenticationException('The provided input is incorrect.');
        } 
    }


}
