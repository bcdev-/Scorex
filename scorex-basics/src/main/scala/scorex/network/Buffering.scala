package scorex.network

import java.net.InetSocketAddress
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

import akka.util.ByteString
import scorex.app.RunnableApplication
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.signatures.SigningFunctions._
import scorex.network.message.MessageHandler.RawNetworkData
import scorex.network.message.MessageSpec
import scorex.utils.ScorexLogging

import scala.annotation.tailrec
import scala.util.{Failure, Success, Try}

trait Buffering extends ScorexLogging {
  //1 MB max packet size
  val MAX_PACKET_LEN: Int = 1024 * 1024

  protected val remote: InetSocketAddress
  protected val application: RunnableApplication
  protected val inbound: Boolean

  private def decryptStream(incoming: ByteString) : ByteString =
    if(incomingDataEncrypted)
      ByteString(inCipher.update(incoming.to[Array]))
    else
      incoming

  protected def handleOutOfBandMessage(spec: MessageSpec[_], msgBytes: Array[Byte]) = Try {
    val repo = application.encryptionMessagesSpecsRepo

    spec.deserializeData(msgBytes) match {
      case Success(content) =>
        spec.messageCode match {
          case repo.EncryptionPubKey.messageCode =>
            handleEncryptionPubKeyMessage(msgBytes)

          case repo.StartEncryption.messageCode =>
            handleStartEncryptionMessage()

          case msgId =>
            log.error(s"No handlers found for an out of bound message: $msgId, this should never happen!")
        }
      case Failure(e) =>
        log.error("Failed to deserialize an out of bound message: " + e.getMessage)
      //TODO: disconnect
    }
  }

  protected val encryptionKeys: (PrivateKey, PublicKey) = generatePrivateKey()
  private var encryptionRemotePublicKey: Option[PublicKey] = None
  private var incomingDataEncrypted = false
  private val inCipher: Cipher = Cipher.getInstance("AES/CFB8/NoPadding")
  private val outCipher: Cipher = Cipher.getInstance("AES/CFB8/NoPadding")

  private def generatePrivateKey(): (PrivateKey, PublicKey) = {
    val rand = new SecureRandom()
    val seed = Array[Byte](32, 0)
    rand.nextBytes(seed)
    EllipticCurveImpl.createKeyPair(seed)
  }

  private def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    require(a.length == b.length, "Byte arrays have to have the same length")

    (a.toList zip b.toList).map(elements => (elements._1 ^ elements._2).toByte).toArray
  } // TODO: Understand this piece of code. :-)

  protected def handleEncryptionPubKeyMessage(content: Any) = {
    val key = content.asInstanceOf[Array[Byte]]
    assert(key.length == EllipticCurveImpl.KeyLength, "Key length is incorrect")
    assert(encryptionRemotePublicKey == None, s"$remote tried to send us a second encryption key")

    encryptionRemotePublicKey = Some(key)

    val sharedSecret = EllipticCurveImpl.createSharedSecret(encryptionKeys._1, key)

    def getPadding = {
      val paddingPattern1 = Array[Byte](0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55)
      val paddingPattern2 = Array[Byte](-86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86,
        -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86)
      if (inbound)
        (paddingPattern1, paddingPattern2)
      else
        (paddingPattern2, paddingPattern1)
    }

    val (inPadding, outPadding) = getPadding

    val inSharedSecret = scorex.crypto.hash.Blake2b256.hash(xor(sharedSecret, inPadding)).slice(0, 16)
    val outSharedSecret = scorex.crypto.hash.Blake2b256.hash(xor(sharedSecret, outPadding)).slice(0, 16)

    val inIV = scorex.crypto.hash.Blake2b256.hash(inSharedSecret).slice(0, 16)
    val outIV = scorex.crypto.hash.Blake2b256.hash(outSharedSecret).slice(0, 16)

    val inSpec = new SecretKeySpec(inSharedSecret, "AES")
    val outSpec = new SecretKeySpec(outSharedSecret, "AES")

    inCipher.init(Cipher.DECRYPT_MODE, inSpec, new IvParameterSpec(inIV))
    outCipher.init(Cipher.ENCRYPT_MODE, outSpec, new IvParameterSpec(outIV))

    log.trace(s"Received remote key from the peer.")
  }

  protected def handleStartEncryptionMessage() = {
    if(encryptionRemotePublicKey != None && incomingDataEncrypted == false) {
      log.trace(s"Starting encrypted channel with $remote")
      incomingDataEncrypted = true
    } else {
      log.trace(s"$remote tried to start encryption twice")
      // TODO: Disconnect
    }
  }

  // TODO: Don't interpret packets twice... Maybe?
  def parseOutOfBandMessage(packet: ByteString) = {
      application.messagesHandler.parseBytes(packet.toByteBuffer) match {
        case Success((spec, msgData)) =>
          if (spec.out_of_band == true) {
            log.trace("Received an out of band message " + spec + " from " + remote)
            handleOutOfBandMessage(spec, msgData) match {
              case Success(e) =>
              case Failure(e) => {
                log.trace(s"$e")
                log.info(s"Out of band message error, disconnecting from $remote")
                // TODO: Disconnect
              }
            }
          }
          true
        case Failure(e) =>
          false
      }
  }

  /**
    * Extracts complete packets of the specified length, preserving remainder
    * data. If there is no complete packet, then we return an empty list. If
    * there are multiple packets available, all packets are extracted, Any remaining data
    * is returned to the caller for later submission
    * @param data A list of the packets extracted from the raw data in order of receipt
    * @return A list of ByteStrings containing extracted packets as well as any remaining buffer data not consumed
    */

  def getPacket(data: ByteString): (List[ByteString], ByteString) = {

    val headerSize = 4

    @tailrec
    def multiPacket(packets: List[ByteString], current: ByteString): (List[ByteString], ByteString) = {
      if (current.length < headerSize) {
        (packets.reverse, current)
      } else {
        val header = decryptStream(current.iterator.getByteString(headerSize))
        val len = header.iterator.getInt(ByteOrder.BIG_ENDIAN)
        if (len > MAX_PACKET_LEN || len < 0) throw new Exception(s"Invalid packet length: $len")
        if (current.length < len + headerSize) {
          (packets.reverse, current)
        } else {
          val packet_chunk = current drop headerSize
          val remaining = packet_chunk drop len
          val content = decryptStream(packet_chunk.iterator.getByteString(len))

          if (parseOutOfBandMessage(content))
            multiPacket(packets, remaining)
          else
            multiPacket(content :: packets, remaining)
        }
      }
    }
    multiPacket(List[ByteString](), data)
  }

}