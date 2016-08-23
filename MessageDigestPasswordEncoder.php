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



require_once 'B2f/Connectizz/Traducteurs/Eliberty/Utils/BasePasswordEncoder.php';
require_once 'B2f/Connectizz/Traducteurs/Eliberty/Utils/EncoderFactoryInterface.php';

/**
 * MessageDigestPasswordEncoder uses a message digest algorithm.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class B2f_Connectizz_Traducteurs_Eliberty_Utils_MessageDigestPasswordEncoder extends B2f_Connectizz_Traducteurs_Eliberty_Utils_BasePasswordEncoder
{
    private $algorithm;
    private $encodeHashAsBase64;
    private $iterations;

    /**
     * Constructor.
     *
     * @param string $algorithm          The digest algorithm to use
     * @param bool   $encodeHashAsBase64 Whether to base64 encode the password hash
     * @param int    $iterations         The number of iterations to use to stretch the password hash
     */
    public function __construct($algorithm = 'sha512', $encodeHashAsBase64 = true, $iterations = 5000)
    {
        $this->algorithm = $algorithm;
        $this->encodeHashAsBase64 = $encodeHashAsBase64;
        $this->iterations = $iterations;
    }

    /**
     * {@inheritdoc}
     */
    public function encodePassword($raw, $salt)
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        if (!in_array($this->algorithm, hash_algos(), true)) {
            throw new Exception(sprintf('The algorithm "%s" is not supported.', $this->algorithm));
        }

        $salted = $this->mergePasswordAndSalt($raw, $salt);
        $digest = hash($this->algorithm, $salted, true);

        // "stretch" hash
        for ($i = 1; $i < $this->iterations; ++$i) {
            $digest = hash($this->algorithm, $digest.$salted, true);
        }

        return $this->encodeHashAsBase64 ? base64_encode($digest) : bin2hex($digest);
    }

    /**
     * {@inheritdoc}
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        return !$this->isPasswordTooLong($raw) && $this->comparePasswords($encoded, $this->encodePassword($raw, $salt));
    }
    
    /* ajout par b2f-concept (Bruno da silva) : 
     * il faut implementer cette methode de l'interface sinon, ça plante : public function getEncoder($user) 
     * Je ne comprends pas comment ça foncitonne coté symfony... vu qu'ils l'ont pas
     */
    public function getEncoder($user) {
    	throw new Exception('methode non implémentée!');
    }
}