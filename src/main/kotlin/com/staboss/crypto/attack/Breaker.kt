package com.staboss.crypto.attack

import com.staboss.crypto.rsa.RSA
import com.staboss.crypto.util.rsaTool
import com.staboss.crypto.util.toBinary
import java.math.BigInteger

fun main(args: Array<String>) {
    val text = if (args.isEmpty()) "SECRET" else args[0]
    val message = text.toBinary().toBigInteger(2)

    val keyPairChosenCipher = rsaTool.generateKeyPair(1024)
    val keyPairCommonModulus = rsaTool.generateKeyPair(32)

    val attacks = mapOf(
            HijackAttack to keyPairChosenCipher,
            LowPublicExponentAttack to keyPairCommonModulus
    )

    val names = mapOf(
            HijackAttack to "Man-in-the-middle attack",
            LowPublicExponentAttack to "Low public exponent attack"
    )

    var rsa: RSA
    var cipher: BigInteger
    var cracked: BigInteger?

    var separator: String
    var attackName: String

    val results = mutableListOf<String>()

    attacks.forEach { (breaker, keyPair) ->
        rsa = RSA(keyPair)
        cipher = rsa.encrypt(message)
        cracked = breaker.attack(cipher, rsa)

        attackName = "* ${names[breaker]} *"
        separator = "*".repeat((names[breaker]?.length ?: 21) + 4)

        val result = "$separator\n$attackName\n$separator\n\n$rsa\n\n" +
                "message = $message\n" +
                "cracked = $cracked\n\n" +
                (if (cracked == message) "Success!" else "Failure!") + "\n"

        results += result
    }

    println("TEST MESSAGE   :  '$text'")
    println("NUMBER FORMAT  :  '$message'\n")
    println(results.joinToString(separator = "\n\n"))
}
