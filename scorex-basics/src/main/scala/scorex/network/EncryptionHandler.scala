package scorex.network

import scorex.app.Application
import scorex.network.NetworkController.DataFromPeer
import scorex.network.message.MessageSpec
import scorex.utils.ScorexLogging
import scorex.crypto.EllipticCurveImpl

class EncryptionHandler(application: Application) extends ViewSynchronizer with ScorexLogging {
  import EncryptionHandler._
  import application.encryptionMessagesSpecsRepo._

  protected lazy override val networkControllerRef = application.networkController
  override val messageSpecs: Seq[MessageSpec[_]] = Seq(EncryptionPubKey, StartEncryption)

  def lol() {
    println("Akka")
  }
  
  override def receive: Receive = {
    case DataFromPeer(msgId, _, connectedPeer) if msgId == EncryptionPubKey.messageCode =>
      {
        log.debug(s"Received an encryption key from ${connectedPeer}")
      }
    case DataFromPeer(msgId, _, connectedPeer) if msgId == StartEncryption.messageCode =>
      {
        log.debug(s"Starting encrypted communication with ${connectedPeer}")
      }
  }
}

object EncryptionHandler {
}