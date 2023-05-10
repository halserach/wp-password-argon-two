<?php

declare(strict_types=1);

namespace TypistTech\WPPasswordArgonTwo;

class PasswordLock extends Validator
{

    /**
     * Password hash options.
     *
     * @var array
     */
    private $options;

    /**
     * PasswordLock constructor.
     *
     * @param string $pepper  Shared secret key used for generating the HMAC variant of the message digest.
     * @param array  $options Password hash options for Argon2i.
     */
    public function __construct(string $pepper, array $options)
    {
        parent::__construct($pepper);

        $this->options = $options;
    }

    /**
     * Checks to see if the supplied hash implements the algorithm and options provided. If not, it is assumed that the
     * hash needs to be rehashed.
     *
     * @param string $ciphertext The hashed password from database.
     *
     * @return bool
     */
    public function needsRehash(string $ciphertext): bool
    {
        return sodium_crypto_pwhash_str_needs_rehash($ciphertext, $this->options['opslimit'], $this->options['memlimit']);
    }

    /**
     * Creates a password hash.
     *
     * @param string $password The user's password in plain text.
     *
     * @return string
     */
    public function hash(string $password): string
    {
        return sodium_crypto_pwhash_str(
            $this->hmac($password),
            $this->options['opslimit'],
            $this->options['memlimit'],
        );
    }
}
