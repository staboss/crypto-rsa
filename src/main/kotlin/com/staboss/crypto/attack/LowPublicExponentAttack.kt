package com.staboss.crypto.attack

import com.staboss.crypto.rsa.RSA
import com.staboss.crypto.util.rsaTool
import java.math.BigInteger

/**
 * Low public exponent attack
 */
object LowPublicExponentAttack : Attack {
    private fun pMod(x: BigInteger, n: BigInteger): BigInteger {
        return (x.pow(2) + BigInteger.ONE).mod(n)
    }

    override fun attack(message: BigInteger, rsa: RSA): BigInteger? {
        val e = rsa.keyPair.publicKey.publicExponent
        val n = rsa.keyPair.publicKey.modulus

        var x = BigInteger("2")
        var y = BigInteger("2")
        var d = BigInteger("1")

        do {
            while (d == BigInteger.ONE) {
                x = pMod(x, n)
                y = pMod(pMod(y, n), n)
                d = (x - y).abs().gcd(n)
            }
            x += BigInteger.ONE
        } while (d == n)

        val q = n / d
        val phi = (d - BigInteger.ONE) * (q - BigInteger.ONE)
        val privateKey = e.modInverse(phi)

        return rsaTool.modularPow(message, privateKey, n)
    }
}
