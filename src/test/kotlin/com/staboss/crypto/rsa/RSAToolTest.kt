package com.staboss.crypto.rsa

import com.staboss.crypto.rsa.RSATool.EEAResult
import com.staboss.crypto.rsa.RSATool.extendedGSD
import com.staboss.crypto.rsa.RSATool.modularPow
import com.staboss.crypto.util.measureTime
import org.junit.Test

import org.junit.Assert.*
import java.math.BigInteger

class RSAToolTest {
    @Test
    fun extendedGSD() {
        assertEquals(
                EEAResult(1.toBigInteger(), 2.toBigInteger(), 13.toBigInteger()),
                extendedGSD(18.toBigInteger(), 7.toBigInteger())
        )
        assertEquals(
                EEAResult(1.toBigInteger(), 13.toBigInteger(), 2.toBigInteger()),
                extendedGSD(7.toBigInteger(), 18.toBigInteger())
        )
        assertNotEquals(
                EEAResult(2.toBigInteger(), 2.toBigInteger(), 13.toBigInteger()),
                extendedGSD(18.toBigInteger(), 7.toBigInteger())
        )
    }

    @Test
    fun modularPow() {
        assertEquals(1.toBigInteger(), modularPow(19.toBigInteger(), 2.toBigInteger(), 18.toBigInteger()))
        assertEquals(6.toBigInteger(), modularPow(27.toBigInteger(), 10.toBigInteger(), 23.toBigInteger()))
        assertEquals(1.toBigInteger(), modularPow(21.toBigInteger(), 100.toBigInteger(), 22.toBigInteger()))
        assertEquals(1.toBigInteger(), modularPow(8.toBigInteger(), 1_000.toBigInteger(), 9.toBigInteger()))
        assertEquals(1.toBigInteger(), modularPow(8.toBigInteger(), 1_000_000_000_000_000.toBigInteger(), 9.toBigInteger()))
    }

    @Test
    fun modularPowBigNumbers() {
        val base = BigInteger.TWO.pow(Int.MAX_VALUE / 4)
        val exponent = "1812744991197698003031144832599386664525371765929351547022046496565049280220311079333023993888736787052381969349623242381236735541598173014158237984549721464476096955870311028937308666857968363840481361031160859116921980149477359742875028752271093305154094243803702949712648540075703105300276357409200498791078105996968312671496107706871331378726257612045852578405647385747725707919045396820205727178527876382724250610127190111762383000585908376041632250982058096841663465160481873862656894900675571726870529415257721446986296635576958877718209437895941147645349019765415105615077947364913422306544633".toBigInteger()
        val modulus = "1918789768038819898645758522071646674198486464083209437732114370433394729513018286461251610877592551288895374711560339755133843772748436805764167694313738118668658098956191131445762708549958372947001969763372191293639922685234559080494238219132530758941837591151793268437662074956655970476689197052845761352781836553032213657615307224816482399199240027414684664541982069711775410724482230967024213057161165864980752039686312878208161967216634158087985361351443962309695097337810982068125906462055355841987772754455088464969323697663941813714356286029398561571897666295720114983340337251411686679798183".toBigInteger()

        val time = measureTime { modularPow(base, exponent, modulus) }
        println("Computed in $time ms")
    }
}