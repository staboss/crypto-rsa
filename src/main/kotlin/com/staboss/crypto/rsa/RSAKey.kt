package com.staboss.crypto.rsa

import java.math.BigInteger

/**
 * RSA KEY
 *
 * @property modulus modulus
 */
interface RSAKey {
    val modulus: BigInteger
}

/**
 * RSA PUBLIC-KEY
 *
 * @property modulus modulus
 * @property publicExponent public exponent
 */
data class RSAPublicKey(override val modulus: BigInteger, val publicExponent: BigInteger) : RSAKey

/**
 * RSA PRIVATE-KEY
 *
 * @property modulus modulus
 * @property privateExponent private exponent
 */
data class RSAPrivateKey(override val modulus: BigInteger, val privateExponent: BigInteger) : RSAKey
