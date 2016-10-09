package scorex.network.message

import scorex.consensus.ConsensusModule
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.signatures.SigningFunctions.PublicKey
import scorex.transaction.TransactionModule

import scala.util.Try


class EncryptionMessagesRepo()(implicit val transactionalModule: TransactionModule[_],
                               consensusModule: ConsensusModule[_]) {

  object EncryptionPubKey extends MessageSpec[PublicKey] {
    override val messageCode: Message.MessageCode = 126: Byte

    override val messageName: String = "EncryptionPubKey message"

    override def out_of_band = true

    override def deserializeData(bytes: Array[Byte]): Try[PublicKey] = Try {
      assert(bytes.length == EllipticCurveImpl.KeyLength, s"Encryption key has a wrong length: ${bytes.length}, should be ${EllipticCurveImpl.KeyLength}")
      bytes
    }

    override def serializeData(publicKey: PublicKey): Array[Byte] = publicKey
  }

  object StartEncryption extends MessageSpec[Unit] {
    override val messageCode: Message.MessageCode = 127: Byte

    override val messageName: String = "StartEncryption message"

    override def out_of_band = true

    override def deserializeData(bytes: Array[Byte]): Try[Unit] =
      Try(require(bytes.isEmpty, "Non-empty data for StartEncryption"))

    override def serializeData(data: Unit): Array[Byte] = Array()
  }

  val specs = Seq(EncryptionPubKey, StartEncryption)
}