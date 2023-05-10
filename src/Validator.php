<?php

declare(strict_types=1);

namespace TypistTech\WPPasswordArgonTwo;

class Validator implements ValidatorInterface
{

    /**
     * Shared secret key used for generating the HMAC variant of the message digest.
     *
     * @var string
     */
    protected $pepper;

    /**
     * PasswordLock constructor.
     *
     * @param string $pepper Shared secret key used for generating the HMAC variant of the message digest.
     */
    public function __construct(string $pepper)
    {
        $this->pepper = $pepper;
    }

    /**
     * Validate user submitted password.
     *
     * @param string $password   The user's password in plain text.
     * @param string $ciphertext Hash of the user's password to check against.
     *
     * @return bool
     */
    public function isValid(string $password, string $ciphertext): bool
    {
        return password_verify(
            $this->hmac($password),
            $ciphertext
        );
    }

    protected function hmac(string $password): string
    {
        return sodium_crypto_generichash($password, $this->pepper); //with blake2b
    }
}
