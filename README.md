# laravelgraphqlsanctm
Making complete authentication system using laravel 10 + graphql lighthouse +Sanctm
Login
Authenticate the user to receive a Bearer token.

mutation {
    login(input: {
        email: "john.doe@gmail.com"
        password: "secret"
    }) {
        token
    }
}
Apply the Authorization header on subsequent calls using the token

  "Authorization": "Bearer 1|lJo1cMhrW9tIUuGwlV1EPjKnvfZKzvgpGgplbwX9"
(Using something other than email? See Custom Identification)

Logout
Revoke the current token.

mutation {
    logout {
        status
        message
    }
}
Register
Successfully registering a user will immediately yield a bearer token (unless email verification is required).

mutation {
    register(input: {
        name: "John Doe"
        email: "john.doe@gmail.com"
        password: "secret"
        password_confirmation: "secret"
    }) {
        token
        status
    }
}
point_up Want to disable password confirmation? Update your schema



When registering a user in combination with the MustVerifyEmail contract you can optionally define the url for email verification. Both __ID__ and __HASH__ will be replaced with the proper values. When use_signed_email_verification_url is enabled in the configuration, the placeholders __EXPIRES__ and __SIGNATURE__ will be replaced.

mutation {
    register(input: {
        name: "John Doe"
        email: "john.doe@gmail.com"
        password: "secret"
        password_confirmation: "secret"
        verification_url: {
            url: "https://my-front-end.com/verify-email?id=__ID__&token=__HASH__"
# Signed:   url: "https://my-front-end.com/verify-email?id=__ID__&token=__HASH__&expires=__EXPIRES__&signature=__SIGNATURE__"
        }
    }) {
        token
        status
    }
}
Email Verification
mutation {
  verifyEmail(input: {
    id: "1"
    hash: "af269947ed80d4a7bc3f78a6dfd05ec369373f9d"
  }) {
    name
    email
  }
}
When use_signed_email_verification_url is enabled in the configuration, the input requires two additional fields.

mutation {
  verifyEmail(input: {
    id: "1"
    hash: "af269947ed80d4a7bc3f78a6dfd05ec369373f9d"
    expires: 1619775828
    signature: "e923636f1093c414aab39f846e9d7a372beefa7b628b28179197e539c56aa0f0"
  }) {
    name
    email
  }
}
Resend Email Verification Link
mutation {
    resendEmailVerification(input: {
        email: "john.doe@gmail.com",
        verification_url: {
            url: "https://my-front-end.com/verify-email?id=__ID__&token=__HASH__"
# Signed:   url: "https://my-front-end.com/verify-email?id=__ID__&token=__HASH__&expires=__EXPIRES__&signature=__SIGNATURE__"
        }
    }) {
        status
    }
}
Forgot Password
Sends a reset password notification.

Optionally use custom reset url using both __EMAIL__ and __TOKEN__ placeholders.

mutation {
    forgotPassword(input: {
        email: "john.doe@gmail.com"
        reset_password_url: {
            url: "https://my-front-end.com/reset-password?email=__EMAIL__&token=__TOKEN__"
        }
    }) {
        status
        message
    }
}
Reset Password
Reset the user's password.

mutation {
    resetPassword(input: {
        email: "john.doe@gmail.com",
        token: "af269947ed80d4a7bc3f78a6dfd05ec369373f9d"
        password: "secret"
        password_confirmation: "secret"
    }) {
        status
        message
    }
}
point_up Want to disable password confirmation? Update your schema



Update Password
Updates the current user's password.

mutation {
    updatePassword(input: {
        current_password: "mypass",
        password: "secret",
        password_confirmation: "secret"
    }) {
        status
    }
}
Custom Identification
You can customize which fields are used for authenticating users.

For example, using username instead of the default email.

/*
|--------------------------------------------------------------------------
| Identification
|--------------------------------------------------------------------------
|
| Configure the credential fields by which the user will be identified.
| Default: email
*/

'user_identifier_field_name' => 'username',
Update the GraphQL schema accordingly

input LoginInput {
    username: String! @rules(apply: ["required"])
}
