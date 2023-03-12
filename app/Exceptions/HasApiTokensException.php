<?php
 
declare(strict_types=1);

namespace App\Exceptions; 

use Exception;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Laravel\Sanctum\Contracts\HasApiTokens;

class HasApiTokensException extends Exception
{
    /**
     * @param Authenticatable|Model $user
     */
    public function __construct($user)
    {
        $message = '"' . get_class($user) . '" must implement "' . HasApiTokens::class . '".';

        parent::__construct($message);
    }
}
