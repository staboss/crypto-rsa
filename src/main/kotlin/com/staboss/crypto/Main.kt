package com.staboss.crypto

import com.staboss.crypto.rsa.RSA
import com.staboss.crypto.rsa.RSAPrivateKey
import com.staboss.crypto.rsa.RSAPublicKey
import com.staboss.crypto.util.errorMessage
import com.staboss.crypto.util.fileHelper
import java.io.File

fun main(args: Array<String>) {
    if (args.contains("-h") || args.isEmpty()) {
        Parser.usage()
        return
    }

    val parser = Parser.getInstance()
    if (!parser.parseArgs(args)) return

    if (parser.generate) {
        val rsa = RSA()

        val publicKeyFile = File("publicKey.csv")
        val privateKeyFile = File("privateKey.csv")

        fileHelper.writeKey(publicKeyFile, rsa.keyPair.publicKey)
        fileHelper.writeKey(privateKeyFile, rsa.keyPair.privateKey)

        println("PUBLIC_KEY  was successfully saved to: \"${publicKeyFile.absolutePath}\"")
        println("PRIVATE_KEY was successfully saved to: \"${privateKeyFile.absolutePath}\"")

        return
    }

    val rsaKey = fileHelper.readKey(parser.secretKeyPath)

    val result = if (parser.encrypt) {
        RSA.encrypt(parser.message, rsaKey as? RSAPublicKey ?: errorMessage("Invalid key format!"))
    } else {
        RSA.decrypt(parser.message, rsaKey as? RSAPrivateKey ?: errorMessage("Invalid key format!"))
    }

    with(parser) {
        if (resultFilePath.isNullOrEmpty()) {
            val file = File(sourceFilePath)
            resultFilePath = file.absolutePath.substring(0, file.absolutePath.lastIndexOf('/')) + "/new_${file.name}"
        }

        val resultFile = File(resultFilePath)
        resultFile.writeText(result)

        println("The result was successfully saved to: \"${resultFile.absolutePath}\"")
    }
}
