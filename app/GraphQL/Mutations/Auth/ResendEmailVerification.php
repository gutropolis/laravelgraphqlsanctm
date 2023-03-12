<?php

namespace App\GraphQL\Mutations\Auth;


use Laravel\Sanctum\Contracts\HasApiTokens;
use App\Exceptions\HasApiTokensException;
use Carbon\Carbon;
use Illuminate\Support\Facades\Log;
use Illuminate\Auth\AuthManager;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr; 
use Nuwave\Lighthouse\Exceptions\AuthenticationException;
use Illuminate\Auth\Events\Registered;


final class ResendEmailVerification
{
    protected AuthManager $authManager;
    protected Config $config;
    protected Hasher $hash;
  
    
    public function __construct(
        AuthManager $authManager,
        Config $config, 
        
    ) {
        $this->authManager              = $authManager;
        $this->config                   = $config;  
    }

    /**
     * @param mixed $_
     * @param array<string, string|int> $args
     * @param GraphQLContext $context
     * @param ResolveInfo $resolveInfo
     * @return array<string, string>
     * @throws Exception
     */
    public function  __invoke($_, array $args): array{
           
        // TODO implement the resolver
        $userProvider = $this->authManager->createUserProvider('users');
        $user = $userProvider->retrieveByCredentials([
            'email' => $args['email'],
        ]);

         
         
        if ($user && $user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()) {
            if (isset($args['verification_url'])) {
                /** @var array<string, string> $verificationUrl */
                $verificationUrl = $args['verification_url'];

                $this->setVerificationUrl($verificationUrl['url']);
            }

            $user->sendEmailVerificationNotification();
        }

        return [
            'status' => 'EMAIL_SENT',
        ];
         
    }

    public function setVerificationUrl(string $url): void
    {
        VerifyEmail::createUrlUsing(function (MustVerifyEmail $user) use ($url) {
            return $this->transformUrl($user, $url);
        });
    }

    public function transformUrl(MustVerifyEmail $user, string $url): string
    {
        $parameters = $this->createUrlParameters($user);

        return str_replace([
            '__ID__',
            '__HASH__',
            '__EXPIRES__',
            '__SIGNATURE__',
        ], $parameters, $url);
    }
    /**
     * @param MustVerifyEmail $user
     * @return mixed[]
     */
    protected function createUrlParameters(MustVerifyEmail $user): array
    {
        $parameters = [
            'id'      => $user()->getKey(),
            'hash'    => $this->createHash($user),
            'expires' => $this->createExpires(),
        ];

        $signature = $this->generate($parameters,$user);

        $values   = array_values($parameters);
        $values[] = $signature;

        return $values;
    }
    protected function createHash(MustVerifyEmail $user): string
    {
        return sha1($user->getEmailForVerification());
    }

    protected function createExpires(): int
    { 
        $expiresIn = $this->config->get('auth.verification.expire', 60);
        return Carbon::now()
            ->addMinutes($expiresIn)
            ->getTimestamp();
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

        try {
            $this->SignatureServiceVerify([
                'id'      => $user()->getKey(),
                'hash'    => $hash,
                'expires' => $expires,
            ], $signature,$user);
        } catch (InvalidSignatureException $exception) {
            throw new AuthenticationException('The provided input is incorrect.');
            
        }
    }
    public function generate(array $params,MustVerifyEmail $user): string
    {
        return hash_hmac('sha256', serialize($params), $user()->appKey);
    }
    public function SignatureServiceVerify(array $params, string $signature,MustVerifyEmail $user): void
    {
        if (! hash_equals($signature, $this->generate($params,$user))) {
            throw new InvalidSignatureException();
        }
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
 

}
