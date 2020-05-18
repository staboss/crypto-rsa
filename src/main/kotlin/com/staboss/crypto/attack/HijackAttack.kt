package com.staboss.crypto.attack

import com.staboss.crypto.rsa.RSA
import java.math.BigInteger

/**
 * Man-in-the-middle attack
 */
object HijackAttack : Attack {
    private val PLAIN_TEXT = BigInteger("2")

    override fun attack(message: BigInteger, rsa: RSA): BigInteger? = with(rsa) {
        val encryptedChosenPlainText = encrypt(PLAIN_TEXT)
        decrypt(encryptedChosenPlainText * message) / PLAIN_TEXT
    }
}
