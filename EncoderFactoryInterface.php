<?php

/*
 * This file is a port of the part of the class MessageDigestPasswordEncoder of the Symfony security package (@see https://raw.githubusercontent.com/symfony/security/master/Core/Encoder/MessageDigestPasswordEncoder.php)
 * il aim to give a php 5.1.2+ compatible version of this hashing algo
 *
 * the original source is (c) Fabien Potencier <fabien@symfony.com>
 * this version is written by Bruno DA SILVA working at b2f-concept.com,
 *
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code of the original version  (https://github.com/symfony/security/blob/master/LICENSE when this was written)
 */




/**
 * EncoderFactoryInterface to support different encoders for different accounts.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
interface B2f_Connectizz_Traducteurs_Eliberty_Utils_PasswordEncoderInterface
{
    /**
     * Returns the password encoder to use for the given account.
     *
     * @param UserInterface|string $user A UserInterface instance or a class name
     *
     * @return PasswordEncoderInterface
     *
     * @throws \RuntimeException when no password encoder could be found for the user
     */
    public function getEncoder($user);
}