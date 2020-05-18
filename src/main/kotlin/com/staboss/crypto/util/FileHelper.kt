package com.staboss.crypto.util

import com.staboss.crypto.rsa.RSAKey
import com.staboss.crypto.rsa.RSAPrivateKey
import com.staboss.crypto.rsa.RSAPublicKey
import java.io.File
import java.math.BigInteger

object FileHelper {

    fun readKey(path: String): RSAKey {
        val file = File(path)
        val lines = file.readLines()
        if (lines.size != 2) errorMessage("Invalid file format!")

        val name = lines[0].split(",")
        val data = lines[1].split(",")

        if (name.size != 2 || data.size != 2) errorMessage("Invalid file format!")

        val key: BigInteger
        val modulus: BigInteger

        try {
            modulus = data[0].toBigInteger()
            key = data[1].toBigInteger()
        } catch (e: Exception) {
            errorMessage("Invalid file data!")
        }

        return when (name[1]) {
            "publicKey" -> RSAPublicKey(modulus, key)
            "privateKey" -> RSAPrivateKey(modulus, key)
            else -> errorMessage("Invalid key format!")
        }
    }

    fun writeKey(file: File, rsaKey: RSAKey) {
        val text = buildString {
            when (rsaKey) {
                is RSAPublicKey -> append("modulus,publicKey\n${rsaKey.modulus},${rsaKey.publicExponent}\n")
                is RSAPrivateKey -> append("modulus,privateKey\n${rsaKey.modulus},${rsaKey.privateExponent}\n")
                else -> errorMessage("Invalid RSA key!")
            }
        }
        file.writeText(text)
    }

    fun readText(path: String) = File(path).readText()

    fun writeText(path: String, text: String) = File(path).writeText(text)
}
