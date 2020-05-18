package com.staboss.crypto.rsa

import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.util.*

object RSATool {

    /**
     * Extended Euclidean algorithm for computing the GCD of large numbers
     *
     * @param r0 non-zero number
     * @param r1 non-zero number
     * @return GCD(r0, r1) and Bezout's coefficients
     */
    fun extendedGSD(r0: BigInteger, r1: BigInteger): EEAResult {
        if (r0 === 0.toBigInteger() || r1 === 0.toBigInteger()) {
            throw InvalidAlgorithmParameterException("0 is an invalid input")
        }

        var a: BigInteger = r0
        var b: BigInteger = r1

        var q = r0 / r1
        var r = r0 % r1

        var s0 = BigInteger.ONE
        var t0 = BigInteger.ZERO

        var s1 = BigInteger.ZERO
        var t1 = BigInteger.ONE

        var tmpS1: BigInteger
        var tmpT1: BigInteger

        while (r > BigInteger.ZERO) {
            // change s0, s1, t0, t1 with new values
            tmpS1 = s1
            tmpT1 = t1
            s1 = s0 - s1 * q
            t1 = t0 - t1 * q
            s0 = tmpS1
            t0 = tmpT1

            // change b -> a and r -> b
            a = b
            b = r

            // go to next computation
            q = a / b
            r = a % b
        }

        if (s1 < BigInteger.ZERO) s1 = r1 + s1
        if (t1 < BigInteger.ZERO) t1 = r0 + t1

        return EEAResult(b, s1, t1)
    }

    /**
     * Fast exponentiation modulo large numbers
     *
     * @param base base
     * @param exponent exponent
     * @param modulus modulus
     * @return base^(exponent) mod (modulus)
     */
    fun modularPow(base: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger {
        if (modulus == BigInteger.ONE) {
            return BigInteger.ZERO
        }

        // exponent binary representation
        val binaryExponent = exponent.toString(2).reversed()
        val list = binaryExponent
                .asSequence()
                .mapIndexed { index, bit -> index to bit }
                .filter { pair -> pair.second == '1' }
                .toMap().keys.toList()

        var counter = 0
        var result = BigInteger.ONE
        var runningPower = base % modulus

        while (BigInteger.TWO.pow(counter) < exponent) {
            // computation base^(2*i) modulo (modulus)
            if (counter > 0) {
                runningPower = (runningPower * runningPower) % modulus
            }

            // check: whether the counter is included in the list of binary parts
            if (list.contains(counter)) {
                result = (result * runningPower) % modulus
            }

            counter++
        }

        return result % modulus
    }

    /**
     * Public and private key generation
     *
     * @return RSA key pair
     */
    fun generateKeyPair(numBits: Int = 1_000): RSA.KeyPair {
        var p = BigInteger.ZERO
        var q = BigInteger.ZERO

        while (!p.isProbablePrime(1024)) {
            p = BigInteger(numBits, Random())
        }
        while (!q.isProbablePrime(1024) || p == q) {
            q = BigInteger(numBits, Random())
        }

        return RSA.generateKeys(p, q)
    }

    /**
     * Wrapper class for storing the result of the Extended Euclidean algorithm
     *
     * @see extendedGSD
     */
    data class EEAResult(val gcd: BigInteger, val s: BigInteger, val t: BigInteger)
}
