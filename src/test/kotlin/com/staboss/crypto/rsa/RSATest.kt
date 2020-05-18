package com.staboss.crypto.rsa

import com.staboss.crypto.rsa.RSA.Companion.decrypt
import com.staboss.crypto.rsa.RSA.Companion.encrypt
import com.staboss.crypto.util.FileHelper.readKey
import org.junit.Assert.assertEquals
import org.junit.Test

class RSATest {
    @Test
    fun `encryption and decryption small numbers test`() {
        val rsa = RSA(929.toBigInteger(), 619.toBigInteger())
        val message = "77"

        val encryptedMessage = rsa.encrypt(message)
        val decryptedMessage = rsa.decrypt(encryptedMessage)

        assertEquals(message, decryptedMessage)
    }

    @Test
    fun `encryption and decryption normal numbers test`() {
        val rsa = RSA(602521.toBigInteger(), 1226741.toBigInteger())
        val message = "Oscar"

        val encryptedMessage = rsa.encrypt(message)
        val decryptedMessage = rsa.decrypt(encryptedMessage)

        assertEquals(message, decryptedMessage)
    }

    @Test
    fun `encryption and decryption big numbers test`() {
        val publicKey = readKey("src/test/resources/publicKey.csv") as RSAPublicKey
        val privateKey = readKey("src/test/resources/privateKey.csv") as RSAPrivateKey

        val message = "Super secret message"

        val encryptedMessage = encrypt(message, publicKey)
        val decryptedMessage = decrypt(encryptedMessage, privateKey)

        assertEquals(message, decryptedMessage)
    }
}