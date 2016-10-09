package scorex.network

import java.net.InetSocketAddress
import java.nio.ByteOrder
import java.security.SecureRandom

import javax.crypto.Cipher
import javax.crypto.spec.{SecretKeySpec, IvParameterSpec}

import akka.util.ByteString
import scorex.crypto.EllipticCurveImpl
import scorex.crypto.signatures.SigningFunctions._
import scorex.utils.ScorexLogging

import scala.annotation.tailrec

trait Buffering extends ScorexLogging {

  //1 MB max packet size
  val MAX_PACKET_LEN: Int = 1024 * 1024

  val remote: InetSocketAddress

  def decryptStream(incoming: ByteString) : ByteString =
    if(incomingDataEncrypted)
      ByteString(inCipher.update(incoming.to[Array]))
    else
      incoming

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
        val len = current.iterator.getInt(ByteOrder.BIG_ENDIAN)
        if (len > MAX_PACKET_LEN || len < 0) throw new Exception(s"Invalid packet length: $len")
        if (current.length < len + headerSize) {
          (packets.reverse, current)
        } else {
          val rem = current drop headerSize // Pop off header
          val (front, back) = rem.splitAt(len) // Front contains a completed packet, back contains the remaining data
          // Pull of the packet and recurse to see if there is another packet available
          multiPacket(front :: packets, back)
        }
      }
    }
    multiPacket(List[ByteString](), data)
  }

  protected var encryptionKeys: (PrivateKey, PublicKey) = generatePrivateKey()
  protected var encryptionRemotePublicKey: Option[PublicKey] = None
  private var incomingDataEncrypted = false
  private val inCipher: Cipher = Cipher.getInstance("AES/CFB8/NoPadding")
  private val outCipher: Cipher = Cipher.getInstance("AES/CFB8/NoPadding")

  private def generatePrivateKey(): (PrivateKey, PublicKey) = {
    val rand = new SecureRandom()
    val seed = Array[Byte](32, 0)
    rand.nextBytes(seed)
    EllipticCurveImpl.createKeyPair(seed)
  }

  def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    require(a.length == b.length, "Byte arrays have to have the same length")

    (a.toList zip b.toList).map(elements => (elements._1 ^ elements._2).toByte).toArray
  } // TODO: Understand this piece of code. :-)

  protected def handleEncryptionPubKeyMessage(content: Any) = {
    val key = content.asInstanceOf[Array[Byte]]
    assert(key.length == EllipticCurveImpl.KeyLength, "Key length is incorrect")
    assert(encryptionRemotePublicKey == None, s"$remote tried to send us a second encryption key")

    encryptionRemotePublicKey = Some(key)

    val sharedSecret = EllipticCurveImpl.createSharedSecret(encryptionKeys._1, key)

    val inPadding = Array[Byte](0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
      0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55)
    val outPadding = Array[Byte](-86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86,
      -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86, -86)

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

}