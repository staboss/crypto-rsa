package com.staboss.crypto.util

import java.util.Base64

object Base64 {
    private val encoder = Base64.getEncoder()
    private val decoder = Base64.getDecoder()

    fun encode(message: String): String {
        val bytes = message.toByteArray(Charsets.UTF_8)
        return encoder.encodeToString(bytes)
    }

    fun decode(message: String): String {
        val bytes = message.toByteArray(Charsets.UTF_8)
        return String(decoder.decode(bytes))
    }
}
