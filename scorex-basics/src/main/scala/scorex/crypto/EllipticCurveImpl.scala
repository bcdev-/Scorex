package scorex.crypto

import scorex.account.PrivateKeyAccount
import scorex.crypto.signatures.SigningFunctions._

object EllipticCurveImpl {
  private val c = scorex.crypto.signatures.Curve25519

  val SignatureLength = c.SignatureLength
  val KeyLength = c.KeyLength

  def createKeyPair(seed: Array[Byte]): (PrivateKey, PublicKey) = c.createKeyPair(seed)

  def sign(account: PrivateKeyAccount, message: MessageToSign): Signature = c.sign(account.privateKey, message)

  def sign(privateKey: PrivateKey, message: MessageToSign): Signature = c.sign(privateKey, message)

  def verify(signature: Signature, message: MessageToSign, publicKey: PublicKey): Boolean = c.verify(signature, message, publicKey)

  def createSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): SharedSecret = c.createSharedSecret(privateKey, publicKey)
}
