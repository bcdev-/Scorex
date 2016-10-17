package scorex.transaction

import com.google.common.primitives.{Bytes, Longs}
import play.api.libs.json.{JsObject, Json}
import scorex.account.{Account, PrivateKeyAccount, PublicKeyAccount}
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.encode.Base58
import scorex.serialization.Deser
import scorex.transaction.TypedTransaction.TransactionType
import scorex.crypto.hash.Blake2b256

import scala.util.Try

@SerialVersionUID(1739417897630221966L)
case class MessageTransaction(timestamp: Long,
                              sender: PublicKeyAccount,
                              recipient: Account,
                              fee: Long,
                              message: Array[Byte],
                              messageHash: Array[Byte],
                              signature: Array[Byte]
                             ) extends SignedTransaction {

  override val transactionType: TransactionType.Value = TransactionType.MessageTransaction

  override val assetFee: (Option[AssetId], Long) = (None, fee)

  lazy val toSign: Array[Byte] = {
    val timestampBytes = Longs.toByteArray(timestamp)
    val feeBytes = Longs.toByteArray(fee)

    Bytes.concat(sender.publicKey, timestampBytes, feeBytes, recipient.bytes, messageHash)
  }
  lazy val notToSign: Array[Byte] = arrayWithSize16bit(message)

  override lazy val json: JsObject = Json.obj(
    "type" -> transactionType.id,
    "id" -> Base58.encode(id),
    "sender" -> sender.address,
    "senderPublicKey" -> Base58.encode(sender.publicKey),
    "recipient" -> recipient.address,
    "fee" -> fee,
    "message" -> Base58.encode(message),
    "messageHash" -> Base58.encode(messageHash),
    "size" -> bytes.length,
    "signature" -> Base58.encode(signature),
    "encrypted" -> false
  )

  override def balanceChanges(): Seq[BalanceChange] = {
    Seq(BalanceChange(AssetAcc(sender, None), -fee))
  }

  override lazy val bytes: Array[Byte] = Bytes.concat(Array(transactionType.id.toByte), signature, toSign, notToSign)

  // 160 bits is secure enough for our needs
  lazy val messageHashValid = messageHash == Blake2b256.hash(message).slice(0, 20)

  def validate: ValidationResult.Value =
    if (!Account.isValid(sender)) {
      ValidationResult.InvalidAddress
    } else if (fee <= 0) {
      ValidationResult.InsufficientFee
    } else if (message.length > MessageTransaction.MaxMessageSize) {
      ValidationResult.MessageTooLong
    } else if (message.length == 0) {
      ValidationResult.MessageEmpty
    } else if (!signatureValid) {
      ValidationResult.InvalidSignature
    } else if (messageHashValid) {
      ValidationResult.MessageHashInvalid
    } else ValidationResult.ValidateOke

}

object MessageTransaction extends Deser[MessageTransaction] {

  val MaxMessageSize = 256

  override def parseBytes(bytes: Array[Byte]): Try[MessageTransaction] = Try {
    require(bytes.head == TransactionType.MessageTransaction.id)
    parseTail(bytes.tail).get
  }

  def parseTail(bytes: Array[Byte]): Try[MessageTransaction] = Try {
    import EllipticCurveImpl._
    val signature = bytes.slice(0, SignatureLength)
    val sender = new PublicKeyAccount(bytes.slice(SignatureLength, SignatureLength + KeyLength))
    val s0 = SignatureLength + KeyLength
    val timestamp = Longs.fromByteArray(bytes.slice(s0, s0 + 8))
    val feeAmount = Longs.fromByteArray(bytes.slice(s0 + 8, s0 + 16))
    val recipient = new Account(Base58.encode(bytes.slice(s0 + 16, s0 + 16 + Account.AddressLength)))
    val s1 = s0 + 16 + Account.AddressLength
    val messageHash = bytes.slice(s1, s1 + 20)
    val (message, _) = parseArraySize16bit(bytes, s1 + 20)
    MessageTransaction(timestamp, sender, recipient, feeAmount, message, messageHash, signature)
  }

  def create(timestamp: Long,
             sender: PrivateKeyAccount,
             recipient: Account,
             feeAmount: Long,
             message: Array[Byte]): MessageTransaction = {
    // 160 bits is surely secure enough for our needs
    lazy val messageHash = Blake2b256.hash(message).slice(0, 20)

    val unsigned = MessageTransaction(timestamp, sender, recipient, feeAmount, message, messageHash, null)
    val sig = EllipticCurveImpl.sign(sender, unsigned.toSign)
    unsigned.copy(signature = sig)
  }
}
