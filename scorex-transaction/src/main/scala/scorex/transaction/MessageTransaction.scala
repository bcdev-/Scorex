package scorex.transaction

import com.google.common.primitives.{Bytes, Longs}
import play.api.libs.json.{JsObject, Json}
import scorex.account.{Account, PrivateKeyAccount, PublicKeyAccount}
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.encode.Base58
import scorex.serialization.Deser
import scorex.transaction.TypedTransaction.TransactionType

import scala.util.Try

@SerialVersionUID(1739417897630221966L)
case class MessageTransaction(timestamp: Long,
                              sender: PublicKeyAccount,
                              recipient: Account,
                              feeAmount: Long,
                              message: Array[Byte],
                              signature: Array[Byte]
                             ) extends SignedTransaction {

  override val transactionType: TransactionType.Value = TransactionType.MessageTransaction

  // Fees are in Waves
  override val assetFee: (Option[AssetId], Long) = (None, feeAmount)

  // Fee is linear based on how long the message is.
  // Every 64 bytes should cost us one standard fee.
  // TODO: Don't hardcode 100000 as a fee, use some other way of determining it.
  val FeeMultiplier = (message.length / 64) + 1
  val MinFee = 100000 * FeeMultiplier

  lazy val toSign: Array[Byte] = {
    val timestampBytes = Longs.toByteArray(timestamp)
    val feeBytes = Longs.toByteArray(feeAmount)

    Bytes.concat(sender.publicKey, timestampBytes, feeBytes, recipient.bytes, arrayWithSize16bit(message))
  }

  override lazy val json: JsObject = Json.obj(
    "type" -> transactionType.id,
    "id" -> Base58.encode(id),
    "sender" -> sender.address,
    "senderPublicKey" -> Base58.encode(sender.publicKey),
    "recipient" -> recipient.address,
    "fee" -> feeAmount,
    "message" -> new String(message),
    "size" -> bytes.length,
    "signature" -> Base58.encode(signature)
  )

  override def balanceChanges(): Seq[BalanceChange] = {
    Seq(BalanceChange(AssetAcc(sender, None), -feeAmount))
  }

  override lazy val bytes: Array[Byte] = Bytes.concat(Array(transactionType.id.toByte), signature, toSign)

  def validate: ValidationResult.Value =
    if (!Account.isValid(sender)) {
      ValidationResult.InvalidAddress
    } else if (feeAmount < MinFee) {
      ValidationResult.InsufficientFee
    } else if (message.length > MessageTransaction.MaxMessageSize) {
      ValidationResult.MessageTooLong
    } else if (message.length == 0) {
      ValidationResult.MessageEmpty
    } else if (!signatureValid) {
      ValidationResult.InvalidSignature
    } else ValidationResult.ValidateOke

}

object MessageTransaction extends Deser[MessageTransaction] {

  val MaxMessageSize = 160

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
    val (message, _) = parseArraySize16bit(bytes, s0 + 16 + Account.AddressLength)
    MessageTransaction(timestamp, sender, recipient, feeAmount, message, signature)
  }

  def create(timestamp: Long,
             sender: PrivateKeyAccount,
             recipient: Account,
             feeAmount: Long,
             message: Array[Byte]): MessageTransaction = {
    val unsigned = MessageTransaction(timestamp, sender, recipient, feeAmount, message, null)
    val sig = EllipticCurveImpl.sign(sender, unsigned.toSign)
    unsigned.copy(signature = sig)
  }
}
