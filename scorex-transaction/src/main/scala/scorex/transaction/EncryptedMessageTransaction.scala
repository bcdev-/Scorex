package scorex.transaction

import java.nio.ByteBuffer

import com.google.common.primitives.{Bytes, Longs}
import play.api.libs.json.{JsObject, Json}
import scorex.account.{Account, PrivateKeyAccount, PublicKeyAccount}
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.encode.{Base58, Base64}
import scorex.crypto.hash.Blake2b256
import scorex.serialization.Deser
import scorex.transaction.TypedTransaction.TransactionType
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

import scorex.wallet.Wallet

import scala.util.Try

@SerialVersionUID(1871481793487177171L)
case class EncryptedMessageTransaction(timestamp: Long,
                                       sender: PublicKeyAccount,
                                       recipient: PublicKeyAccount,
                                       feeAmount: Long,
                                       rawMessage: Array[Byte],
                                       rawMessageHash: Array[Byte],
                                       nonce: Array[Byte],
                                       signature: Array[Byte]
                                      ) extends SignedTransaction {

  override val transactionType: TransactionType.Value = TransactionType.EncryptedMessageTransaction

  override val assetFee: (Option[AssetId], Long) = (None, feeAmount)

  def decrypt(wallet: Wallet): Option[Array[Byte]] = {
    val timestampArray = ByteBuffer.allocate(java.lang.Long.SIZE / java.lang.Byte.SIZE).putLong(timestamp).array()

    var sharedSecret = Array[Byte]()
    val senderAccount = wallet.privateKeyAccount(Account.fromPublicKey(sender.publicKey).address)
    if(senderAccount.isDefined)
      sharedSecret = EllipticCurveImpl.createSharedSecret(senderAccount.get.privateKey, recipient.publicKey)
    else {
      val recipientAccount = wallet.privateKeyAccount(Account.fromPublicKey(recipient.publicKey).address)
      if(recipientAccount.isDefined)
        sharedSecret = EllipticCurveImpl.createSharedSecret(recipientAccount.get.privateKey, sender.publicKey)
    }
    if (sharedSecret.isEmpty)
      return None
    val encryptionKey = Blake2b256.hash(Bytes.concat(sharedSecret, timestampArray, nonce)).slice(0, 16)
    val iv = Blake2b256.hash(encryptionKey).slice(0, 16)

    val cipher: Cipher = Cipher.getInstance("AES/CFB8/NoPadding")
    val secretKeySpec = new SecretKeySpec(encryptionKey, "AES")
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv))
    val rawDecryptedMessage = cipher.update(rawMessage)

    val padding = rawDecryptedMessage.apply(0)
    Some(rawDecryptedMessage.slice(1, rawDecryptedMessage.length - padding))
  }

  lazy val toSign: Array[Byte] = {
    val timestampBytes = Longs.toByteArray(timestamp)
    val feeBytes = Longs.toByteArray(feeAmount)

    Bytes.concat(sender.publicKey, recipient.publicKey, timestampBytes, feeBytes, rawMessageHash)
  }
  lazy val notToSign: Array[Byte] = Bytes.concat(nonce, arrayWithSize16bit(rawMessage))

  override lazy val json: JsObject = Json.obj(
    "type" -> transactionType.id,
    "id" -> Base58.encode(id),
    "sender" -> sender.address,
    "senderPublicKey" -> Base58.encode(sender.publicKey),
    "recipient" -> recipient.address,
    "recipientPublicKey" -> Base58.encode(recipient.publicKey),
    "fee" -> feeAmount,
    "nonce" -> Base64.encode(nonce),
    "rawMessage" -> Base64.encode(rawMessage),
    "rawMessageHash" -> Base58.encode(rawMessageHash),
    "size" -> bytes.length,
    "signature" -> Base58.encode(signature),
    "encrypted" -> true
  )

  override def jsonWithWallet(wallet: Wallet): JsObject = {
    val message = decrypt(wallet)
    if (message.isDefined)
      json ++ Json.obj("message" -> new String(message.get))
    else
      json
  }

  override def balanceChanges(): Seq[BalanceChange] = {
    Seq(BalanceChange(AssetAcc(sender, None), -feeAmount))
  }

  override lazy val bytes: Array[Byte] = Bytes.concat(Array(transactionType.id.toByte), signature, toSign, notToSign)

  // 160 bits is secure enough for our needs
  lazy val messageHashValid = java.util.Arrays.equals(Blake2b256.hash(Bytes.concat(nonce, rawMessage)).slice(0, 20), rawMessageHash)

  def validate: ValidationResult.Value = {
    val l = EllipticCurveImpl.verify(signature, toSign, sender.publicKey)
    if (!Account.isValid(sender)) {
      ValidationResult.InvalidAddress
    } else if (feeAmount <= 0) {
      ValidationResult.InsufficientFee
    } else if (rawMessage.length > EncryptedMessageTransaction.MaxMessageSize + EncryptedMessageTransaction.VanityHeaderSize) {
      ValidationResult.MessageTooLong
    } else if (rawMessage.length <= EncryptedMessageTransaction.VanityHeaderSize) {
      ValidationResult.MessageEmpty
    } else if ((rawMessage.length - EncryptedMessageTransaction.VanityHeaderSize) % EncryptedMessageTransaction.MessageAlign != 0) {
      ValidationResult.MessageNotAligned
    } else if (nonce.length != EncryptedMessageTransaction.NonceLength) {
      ValidationResult.NonceLengthIncorrect
    } else if (!messageHashValid) {
      ValidationResult.MessageHashInvalid
    } else if (!signatureValid) {
      ValidationResult.InvalidSignature
    } else ValidationResult.ValidateOke
  }
}

object EncryptedMessageTransaction extends Deser[EncryptedMessageTransaction] {

  val MaxMessageSize = 256
  val VanityHeaderSize = 1
  val MessageAlign = 32
  val NonceLength = 8

  override def parseBytes(bytes: Array[Byte]): Try[EncryptedMessageTransaction] = Try {
    require(bytes.head == TransactionType.EncryptedMessageTransaction.id)
    parseTail(bytes.tail).get
  }

  def parseTail(bytes: Array[Byte]): Try[EncryptedMessageTransaction] = Try {
    import EllipticCurveImpl._
    val signature = bytes.slice(0, SignatureLength)
    val sender = new PublicKeyAccount(bytes.slice(SignatureLength, SignatureLength + KeyLength))
    val s0 = SignatureLength + KeyLength
    val recipient = new PublicKeyAccount(bytes.slice(s0, s0 + KeyLength))
    val s1 = s0 + KeyLength
    val timestamp = Longs.fromByteArray(bytes.slice(s1, s1 + 8))
    val feeAmount = Longs.fromByteArray(bytes.slice(s1 + 8, s1 + 16))
    val rawMessageHash = bytes.slice(s1 + 16, s1 + 16 + 20)
    val s2 = s1 + 16 + 20
    val nonce = bytes.slice(s2, s2 + NonceLength)
    val (rawMessage, _) = parseArraySize16bit(bytes, s2 + NonceLength)
    EncryptedMessageTransaction(timestamp, sender, recipient, feeAmount, rawMessage, rawMessageHash, nonce, signature)
  }

  def create(timestamp: Long,
             sender: PrivateKeyAccount,
             recipient: PublicKeyAccount,
             feeAmount: Long,
             rawMessage: Array[Byte],
             nonce: Array[Byte]
            ): EncryptedMessageTransaction = {
    lazy val rawMessageHash = Blake2b256.hash(Bytes.concat(nonce, rawMessage)).slice(0, 20)

    val unsigned = EncryptedMessageTransaction(timestamp, sender, recipient, feeAmount, rawMessage, rawMessageHash, nonce, null)
    val sig = EllipticCurveImpl.sign(sender, unsigned.toSign)
    unsigned.copy(signature = sig)
  }

  private def makeNonce(): Array[Byte] = {
    val rand = new SecureRandom()
    val seed = Array.fill[Byte](NonceLength)(0)
    rand.nextBytes(seed)
    seed
  }

  private def encryptMessage(timestamp: Long,
                             sender: PrivateKeyAccount,
                             recipient: PublicKeyAccount,
                             message: Array[Byte]): (Array[Byte], Array[Byte], Array[Byte]) = {
    val rand = new SecureRandom()
    val nonce = makeNonce()
    val timestampArray = ByteBuffer.allocate(java.lang.Long.SIZE / java.lang.Byte.SIZE).putLong(timestamp).array()

    val padding = MessageAlign - (message.length % MessageAlign)
    val paddingRandom = Array.fill[Byte](padding)(0)
    rand.nextBytes(paddingRandom)

    val rawDecryptedMessage = Array[Byte](padding.toByte) ++ message ++ paddingRandom

    val sharedSecret = EllipticCurveImpl.createSharedSecret(sender.privateKey, recipient.publicKey)
    val encryptionKey = Blake2b256.hash(Bytes.concat(sharedSecret, timestampArray, nonce)).slice(0, 16)
    val iv = Blake2b256.hash(encryptionKey).slice(0, 16)

    val cipher: Cipher = Cipher.getInstance("AES/CFB8/NoPadding")
    val secretKeySpec = new SecretKeySpec(encryptionKey, "AES")
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv))
    val rawMessage = cipher.update(rawDecryptedMessage)

    val rawMessageHash = Blake2b256.hash(Bytes.concat(nonce, rawMessage)).slice(0, 20)

    (rawMessage, rawMessageHash, nonce)
  }

  def createAndEncrypt(timestamp: Long,
             sender: PrivateKeyAccount,
             recipient: PublicKeyAccount,
             feeAmount: Long,
             message: Array[Byte]
            ): EncryptedMessageTransaction = {
    val (rawMessage, rawMessageHash, nonce) = encryptMessage(timestamp, sender, recipient, message)

    val unsigned = EncryptedMessageTransaction(timestamp, sender, recipient, feeAmount, rawMessage, rawMessageHash, nonce, null)
    val sig = EllipticCurveImpl.sign(sender, unsigned.toSign)
    unsigned.copy(signature = sig)
  }
}
