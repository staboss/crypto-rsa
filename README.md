# Pure Kotlin implementation of RSA-cryptosystem
**RSA (Rivest–Shamir–Adleman)** is one of the first public-key cryptosystems and is widely used for secure data transmission. 
In such a cryptosystem, the encryption key is public and distinct from the decryption key which is kept secret (private). 
In RSA, this asymmetry is based on the practical difficulty of factoring the product of two large prime numbers.

See [wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem) for more information.

## Requirements
- [JAVA 8+](https://www.java.com/en/download/)
- [GRADLE](https://docs.gradle.org/current/userguide/installation.html#installing_with_a_package_manager)

## Minimal modifications
- Fast exponentiation modulo algorithm ([wikipedia](https://en.wikipedia.org/wiki/Modular_exponentiation))

## Build project
    ➜  crypto-rsa: gradle build
    ➜  ...
    ➜  crypto-rsa: gradle jar

## Usage 

    usage: java -jar crypto-rsa.jar -e|-d -s FILE [-r FILE] -k KEY

```
optional arguments:
  -d         : decrypt message
  -e         : encrypt message
  -k KEY     : secret key file
  -s FILE    : source file
  -r FILE    : result file
```

## Examples
- Key generation
```
➜  java -jar crypto-rsa.jar -g
```
- Encryption
```
➜  java -jar crypto-rsa.jar -e -s plaintext.txt -r ciphertext.txt -k publicKey.csv
```
- Decryption
```
➜  java -jar crypto-rsa.jar -d -s ciphertext.txt -r plaintext.txt -k privateKey.csv
```

You can find detailed examples [here](https://github.com/staboss/crypto-rsa/tree/master/example) :)

## Implemented attacks
- Man-in-the-middle attack
- Low public exponent attack

Try to hack with `rsa-attack.jar` in the [lib](https://github.com/staboss/crypto-rsa/tree/master/lib) directory :)
### Simple usage

    ➜  lib: java -jar rsa-attack.jar [MESSAGE]

## License & copyright
Licensed under the [MIT-License](LICENSE.md).