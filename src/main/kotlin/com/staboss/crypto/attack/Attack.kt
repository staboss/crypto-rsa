package com.staboss.crypto.attack

import com.staboss.crypto.rsa.RSA
import java.math.BigInteger

interface Attack {
    fun attack(message: BigInteger, rsa: RSA): BigInteger?
}
