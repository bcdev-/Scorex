package scorex.transaction

import org.scalacheck.Gen
import org.scalatest._
import org.scalatest.prop.PropertyChecks
import scorex.account.PrivateKeyAccount
import scorex.crypto.encode.Base58
import scorex.wallet.Wallet

class EncryptedMessageTransactionSpecification extends PropSpec with PropertyChecks with Matchers with TransactionGen {

  def genRandomMessage(): Gen[Array[Byte]] = {
    val mul = scala.util.Random.nextInt(4) + 1
    genBoundedBytes(1 + mul * 32, 1 + mul * 32)
  }

  val rawEncryptedMessageGenerator: Gen[EncryptedMessageTransaction] = for {
    sender: PrivateKeyAccount <- accountGen
    recipient: PrivateKeyAccount <- accountGen
    raw_message <- genRandomMessage()
    nonce <- genBoundedBytes(EncryptedMessageTransaction.NonceLength, EncryptedMessageTransaction.NonceLength)
    fee <- positiveLongGen
    timestamp <- positiveLongGen
  } yield {
    EncryptedMessageTransaction.create(timestamp, sender, recipient, fee, raw_message, nonce)
  }

  property("EncryptedMessageTransaction serialization roundtrip") {
    forAll(rawEncryptedMessageGenerator) { issue: EncryptedMessageTransaction =>
      val recovered = EncryptedMessageTransaction.parseBytes(issue.bytes).get
      issue.validate shouldEqual ValidationResult.ValidateOke
      recovered.validate shouldEqual ValidationResult.ValidateOke
      recovered.bytes shouldEqual issue.bytes
      issue.rawMessage shouldEqual recovered.rawMessage
    }
  }

  val encryptedMessageGenerator: Gen[EncryptedMessageTransaction] = for {
    sender: PrivateKeyAccount <- accountGen
    recipient: PrivateKeyAccount <- accountGen
    message <- genRandomMessage()
    fee <- positiveLongGen
    timestamp <- positiveLongGen
  } yield {
    EncryptedMessageTransaction.createAndEncrypt(timestamp, sender, recipient, fee, message)
  }

  property("EncryptedMessageTransaction key in wallet decryption") {
    forAll(encryptedMessageGenerator) { issue: EncryptedMessageTransaction =>
      val recovered = EncryptedMessageTransaction.parseBytes(issue.bytes).get
      issue.validate shouldEqual ValidationResult.ValidateOke
      recovered.validate shouldEqual ValidationResult.ValidateOke
      recovered.bytes shouldEqual issue.bytes
      issue.rawMessage shouldEqual recovered.rawMessage
    }
  }

  property("EncryptedMessageTransaction known value encryption/decryption") {
    val w = new Wallet(None, "cookies", Base58.decode("FQgbSAm6swGbtqA3NE8PttijPhT4N3Ufh4bHFAkyVnQz").toOption)
    val known1 = w.generateNewAccount().get
    val known2 = w.generateNewAccount().get
    val unknown1 = new PrivateKeyAccount(Array[Byte](1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2))
    val unknown2 = new PrivateKeyAccount(Array[Byte](5, 4, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2))

    val timestamp = 10293561
    val fee = 19399541
    val message = "What a beautiful message! I'm really jealous. :-)".getBytes()

    var tx = EncryptedMessageTransaction.createAndEncrypt(timestamp, unknown1, unknown2, fee, message)
    tx.decrypt(w).isDefined shouldEqual false
    tx = EncryptedMessageTransaction.createAndEncrypt(timestamp, known1, known2, fee, message)
    tx.decrypt(w).get shouldEqual message
    tx = EncryptedMessageTransaction.createAndEncrypt(timestamp, unknown1, known2, fee, message)
    tx.decrypt(w).get shouldEqual message
    tx = EncryptedMessageTransaction.createAndEncrypt(timestamp, known1, unknown2, fee, message)
    tx.decrypt(w).get shouldEqual message
  }

}
