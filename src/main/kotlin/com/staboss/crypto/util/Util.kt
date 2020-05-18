package com.staboss.crypto.util

import com.staboss.crypto.rsa.RSATool
import java.math.BigInteger
import kotlin.system.exitProcess

val base64 = Base64
val rsaTool = RSATool
val fileHelper = FileHelper

/**
 * Supplements the binary sequence with zeros
 *
 * @param bits coding
 * @return binary representation multiple [bits]
 */
fun String.toCorrectBinaryLength(bits: Int = 8) = "0".repeat(bits - length % bits) + this

/**
 * Converts a number to its binary representation
 *
 * @param bits coding
 * @return binary representation of a number
 */
fun Int.toBinary(bits: Int = 8): String = toString(radix = 2).toCorrectBinaryLength(bits)

/**
 * Converts a character to its binary representation
 *
 * @param bits coding
 * @return binary representation of a character
 */
fun Char.toBinary(bits: Int = 8): String = toInt().toString(radix = 2).toCorrectBinaryLength(bits)

/**
 * Преобразует строку в двоичное представление
 *
 * @param bits coding
 * @return string of bits
 */
fun String.toBinary(bits: Int = 8): String =
        map { char -> char.toBinary(bits) }
                .flatMap { binaryString -> binaryString.toList() }
                .map { bit -> bit.toString().toInt() }
                .joinToString("")

/**
 * Converts a string of bits to text
 *
 * @param bits coding
 * @return text
 */
fun String.toText(bits: Int = 8): String =
        toCorrectBinaryLength(bits)
                .chunked(bits)
                .map { binaryString -> binaryString.toInt(radix = 2).toChar() }
                .joinToString("")

/**
 * Converts a large number to text
 *
 * @param bits coding
 * @return text
 */
fun BigInteger.toText(bits: Int = 8): String = toString(2).toText(bits)

/**
 * Error output
 *
 * @param message error message
 */
fun errorMessage(message: String): Nothing {
    System.err.println(message)
    exitProcess(1)
}

/**
 * Measures the time of some [action]
 *
 * @param action some kind of process
 * @return time in ms
 */
inline fun measureTime(action: () -> Unit): Long {
    val startTime = System.currentTimeMillis()
    action.invoke()
    val endTime = System.currentTimeMillis()
    return endTime - startTime
}
