package com.staboss.crypto.rsa

import com.staboss.crypto.util.*
import java.math.BigInteger

/**
 * RSA (Rivest–Shamir–Adleman) is one of the first public-key cryptosystems
 * and is widely used for secure data transmission. In such a cryptosystem,
 * the encryption key is public and distinct from the decryption key which
 * is kept secret (private).
 *
 * In RSA, this asymmetry is based on the practical difficulty of factoring
 * the product of two large prime numbers, the "factoring problem".
 *
 * @property keyPair PUBLIC & PRIVATE KEYS
 */
class RSA {

    var keyPair: KeyPair

    constructor() {
        keyPair = rsaTool.generateKeyPair()
    }

    constructor(keyPair: KeyPair) {
        this.keyPair = keyPair
    }

    constructor(p: BigInteger, q: BigInteger) {
        keyPair = generateKeys(p, q)
    }

    constructor(modulus: BigInteger, publicKey: BigInteger, privateKey: BigInteger) {
        keyPair = KeyPair(RSAPublicKey(modulus, publicKey), RSAPrivateKey(modulus, privateKey))
    }

    companion object {
        /**
         * Algorithm for creating PUBLIC & PRIVATE KEYS
         *
         * @param p random prime number
         * @param q random prime number
         */
        fun generateKeys(p: BigInteger, q: BigInteger): KeyPair {
            if (!p.isProbablePrime(20) || !q.isProbablePrime(20) || p === q) {
                errorMessage("p and q have to be two distinct primes!")
            }

            // compute modulus: n = p * q
            val n = p * q

            // compute Euler's function: φ(n) = (p - 1) * (q - 1)
            val phi = (p - BigInteger.ONE) * (q - BigInteger.ONE)

            // pick the public exponent 'e' from the range (1, φ), 'e' is coprime to the value of the function φ(n)
            val e = BigInteger.valueOf(65537)

            // computes the private exponent 'd' multiplicative inverse to the number 'e' modulo φ(n)
            val d = rsaTool.extendedGSD(phi, e).t

            // the number 'd' number must satisfy the comparison: d * e ≡ 1 mod φ(n)
            val modED = (e * d) % phi
            if (modED != BigInteger.ONE) error("Invalid KeyPair: e * d mod φ(n) = $modED")

            val publicKey = RSAPublicKey(n, e)
            val privateKey = RSAPrivateKey(n, d)

            return KeyPair(publicKey, privateKey)
        }

        /**
         * Encryption
         *
         * @param message plaintext
         * @param modulus modulus
         * @param publicExponent public exponent
         * @return Base64 encoded ciphertext
         */
        fun encrypt(message: String, modulus: BigInteger, publicExponent: BigInteger): String {
            val publicKey = createPublicKey(modulus, publicExponent)
            return encrypt(message, publicKey)
        }

        /**
         * Encryption
         *
         * @param message plaintext
         * @param publicKey PUBLIC KEY
         * @return Base64 encoded ciphertext
         */
        fun encrypt(message: String, publicKey: RSAPublicKey): String {
            val plainText = message.toBinary().toBigInteger(2)
            val cipherText = rsa(plainText, publicKey.publicExponent, publicKey.modulus).toString(16)
            return base64.encode(cipherText)
        }

        /**
         * Decryption
         *
         * @param message Base64 encoded ciphertext
         * @param modulus modulus
         * @param privateExponent private exponent
         * @return plaintext
         */
        fun decrypt(message: String, modulus: BigInteger, privateExponent: BigInteger): String {
            val privateKey = createPrivateKey(modulus, privateExponent)
            return decrypt(message, privateKey)
        }

        /**
         * Decryption
         *
         * @param message Base64 encoded ciphertext
         * @param privateKey PRIVATE KEY
         * @return plaintext
         */
        fun decrypt(message: String, privateKey: RSAPrivateKey): String {
            val cipherText = base64.decode(message).toBigInteger(16)
            val plainText = rsa(cipherText, privateKey.privateExponent, privateKey.modulus)
            return plainText.toText()
        }

        /**
         * Fast exponentiation modulo
         *
         * @param message base
         * @param exponent exponent
         * @param modulus modulus
         * @return message^(exponent) modulo (modulus)
         */
        private fun rsa(message: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger {
            return rsaTool.modularPow(message, exponent, modulus)
        }

        /**
         * Fast exponentiation modulo
         *
         * @param message base
         * @param rsaKey RSA KEY
         * @return message^(rsaKey.exponent) modulo (rsaKey.modulus)
         */
        private fun rsa(message: BigInteger, rsaKey: RSAKey): BigInteger = when (rsaKey) {
            is RSAPublicKey -> rsa(message, rsaKey.publicExponent, rsaKey.modulus)
            is RSAPrivateKey -> rsa(message, rsaKey.privateExponent, rsaKey.modulus)
            else -> errorMessage("Invalid RSA key!")
        }

        /**
         * Creating a PUBLIC KEY
         *
         * @param modulus modulus
         * @param publicExponent public exponent
         * @return RSA PUBLIC KEY
         */
        private fun createPublicKey(modulus: BigInteger, publicExponent: BigInteger): RSAPublicKey {
            return RSAPublicKey(modulus, publicExponent)
        }

        /**
         * Creating a PRIVATE KEY
         *
         * @param modulus modulus
         * @param privateExponent private exponent
         * @return RSA PRIVATE KEY
         */
        private fun createPrivateKey(modulus: BigInteger, privateExponent: BigInteger): RSAPrivateKey {
            return RSAPrivateKey(modulus, privateExponent)
        }
    }

    /**
     * Encryption
     *
     * @param message plaintext in numerical representation
     * @return ciphertext in numerical representation
     */
    fun encrypt(message: BigInteger): BigInteger {
        return rsa(message, keyPair.publicKey)
    }

    /**
     * Encryption
     *
     * @param message plaintext
     * @return Base64 encoded ciphertext
     */
    fun encrypt(message: String): String {
        val plainText = message.toBinary().toBigInteger(2)
        val cipherText = rsa(plainText, keyPair.publicKey).toString(16)
        return base64.encode(cipherText)
    }

    /**
     * Decryption
     *
     * @param message ciphertext in numerical representation
     * @return plaintext in numerical representation
     */
    fun decrypt(message: BigInteger): BigInteger {
        return rsa(message, keyPair.privateKey)
    }

    /**
     * Decryption
     *
     * @param message Base64 encoded ciphertext
     * @return plaintext
     */
    fun decrypt(message: String): String {
        val cipherText = message.toBigInteger(16)
        val plainText = rsa(cipherText, keyPair.privateKey)
        return plainText.toText()
    }

    /**
     * PUBLIC & PRIVATE KEYS
     *
     * @property publicKey PUBLIC KEY
     * @property privateKey PRIVATE KEY
     */
    data class KeyPair(val publicKey: RSAPublicKey, val privateKey: RSAPrivateKey)

    override fun toString(): String = "e = ${keyPair.publicKey.publicExponent}\n" +
            "d = ${keyPair.privateKey.privateExponent}\n" +
            "n = ${keyPair.privateKey.modulus}"
}