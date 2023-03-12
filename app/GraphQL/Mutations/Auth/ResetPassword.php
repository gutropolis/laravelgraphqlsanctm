<?php

namespace App\GraphQL\Mutations\Auth;
use App\Exceptions\GraphQLValidationException;
use Illuminate\Auth\Events\PasswordReset; 
use Illuminate\Contracts\Events\Dispatcher;
use GraphQL\Type\Definition\ResolveInfo;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Support\Arr;
use Illuminate\Auth\Notifications\ResetPassword as ResetPasswordNotification; 
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;

final class ResetPassword
{
    protected Dispatcher $dispatcher;
    protected PasswordBroker $passwordBroker;
    protected Translator $translator;
    protected Hasher $hash;
     
    public function __construct(
        PasswordBroker $passwordBroker,
        Translator $translator, Hasher $hash, Dispatcher $dispatcher
    ) {
        $this->passwordBroker       = $passwordBroker;
        $this->translator           = $translator; 
        $this->hash       = $hash;
        $this->dispatcher = $dispatcher;
    }


  
    /**
     * @param  null  $_
     * @param  array{}  $args
     */
    public function __invoke($_, array $args, GraphQLContext $context, ResolveInfo $resolveInfo): array
    { 

        $credentials = Arr::except($args, [
            'directive',
            'password_confirmation',
        ]);

        /** @var string $response */
        $response = $this->passwordBroker->reset($credentials, function (Authenticatable $user, string $password) {
            $this->resetPassword($user, $password);
        });

        /** @var string $message */
        $message = $this->translator->get($response);

        if ($response === PasswordBroker::PASSWORD_RESET) {
            return [
                'status'  => 'PASSWORD_RESET',
                'message' => $message,
            ];
        }

        throw new GraphQLValidationException(
            $message,
            $this->getInvalidField($response),
            $resolveInfo,
        );
 
    }

    protected function getInvalidField(string $response): string
    {
        switch ($response) {
            case PasswordBroker::INVALID_USER:
                return 'email';

            case PasswordBroker::INVALID_TOKEN:
                return 'token';

            default:
                return '';
        }
    }

    public function transformUrl(CanResetPassword $notifiable, string $token, string $url): string
    {
        return str_replace([
            '__EMAIL__',
            '__TOKEN__',
        ], [
            $notifiable->getEmailForPasswordReset(),
            $token,
        ], $url);
    }

    public function setResetPasswordUrl(string $url): void
    {
        ResetPasswordNotification::createUrlUsing(function (CanResetPassword $notifiable, string $token) use ($url): string {
            return $this->transformUrl($notifiable, $token, $url);
        });
    }

    public function resetPassword($user, string $password): void
    {
        /** @var Model $user */
        $this->updateUser($user, $password);

        /** @var Authenticatable $user */
        $this->dispatcher->dispatch(new PasswordReset($user));
    }

    protected function updateUser(Model $user, string $password): void
    {
        $user->setAttribute('password', $this->hash->make($password));
        $user->save();
    }
}
