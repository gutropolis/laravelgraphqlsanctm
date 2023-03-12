<?php

namespace App\GraphQL\Mutations\Auth; 
use Illuminate\Support\Facades\Password; 
use Illuminate\Auth\Notifications\ResetPassword as ResetPasswordNotification; 
use Illuminate\Contracts\Auth\CanResetPassword; 
final class ForgotPassword
{
    /**
     * @param  null  $_
     * @param  array{}  $args
     */
    public function __invoke($_, array $args) {

        if (isset($args['reset_password_url'])) {
            /** @var array<string, string> $resetPasswordUrl */
            $resetPasswordUrl = $args['reset_password_url']; 
            $this->setResetPasswordUrl($resetPasswordUrl['url']);
        }
        Password::sendResetLink([  'email' => $args['email'] ]);
         /** @var string $message */
         $message = 'Reset password link sent on your email id.';

         return [
             'status'  => 'EMAIL_SENT',
             'message' => $message,
         ]; 
    }
    public function setResetPasswordUrl(string $url): void
    {
        ResetPasswordNotification::createUrlUsing(function (CanResetPassword $notifiable, string $token) use ($url): string {
            return $this->transformUrl($notifiable, $token, $url);
        });
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
}
