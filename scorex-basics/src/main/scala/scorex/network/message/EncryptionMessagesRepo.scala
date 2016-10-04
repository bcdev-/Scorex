package scorex.network.message

import java.net.{InetAddress, InetSocketAddress}
import java.util

import com.google.common.primitives.{Bytes, Ints}
import scorex.block.Block
import scorex.consensus.ConsensusModule
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.singing.SigningFunctions
import scorex.crypto.singing.SigningFunctions.Signature
import scorex.network.message.Message._
import scorex.transaction.{History, TransactionModule}

import scala.util.Try


class EncryptionMessagesRepo()(implicit val transactionalModule: TransactionModule[_],
                          consensusModule: ConsensusModule[_]) {

  object EncryptionPubKey extends MessageSpec[Unit] {
    override val messageCode: Message.MessageCode = 126: Byte

    override val messageName: String = "EncryptionPubKey message"

    override def deserializeData(bytes: Array[Byte]): Try[Unit] = Try {
      val debug = bytes.length
      assert(debug == EllipticCurveImpl.KeyLength, s"Encryption key has a wrong length: ${debug}, should be ${EllipticCurveImpl.KeyLength}")
      bytes
    }
    
    override def serializeData(data: Unit): Array[Byte] = Array()
    
    override def out_of_band = true
  }

  object StartEncryption extends MessageSpec[Unit] {
    override val messageCode: Message.MessageCode = 127: Byte

    override val messageName: String = "StartEncryption message"

    override def deserializeData(bytes: Array[Byte]): Try[Unit] = 
      Try(require(bytes.isEmpty, "Non-empty data for StartEncryption"))
    
    override def serializeData(data: Unit): Array[Byte] = Array()
    
    override def out_of_band = true
  }

  val specs = Seq(EncryptionPubKey, StartEncryption)
}