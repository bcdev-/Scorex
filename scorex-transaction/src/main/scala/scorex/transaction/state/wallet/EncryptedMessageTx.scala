package scorex.transaction.state.wallet

import play.api.libs.functional.syntax._
import play.api.libs.json.{JsPath, Reads, Writes}

case class EncryptedMessageTx(fee: Long, sender: String, recipientPublicKey: String, message: String)

object EncryptedMessageTx {
  implicit val messageWrites: Writes[EncryptedMessageTx] = (
    (JsPath \ "fee").write[Long] and
      (JsPath \ "sender").write[String] and
      (JsPath \ "recipientPublicKey").write[String] and
      (JsPath \ "message").write[String]
    ) (unlift(EncryptedMessageTx.unapply))

  implicit val messageReads: Reads[EncryptedMessageTx] = (
    (JsPath \ "fee").read[Long] and
      (JsPath \ "sender").read[String] and
      (JsPath \ "recipientPublicKey").read[String] and
      (JsPath \ "message").read[String]
    ) (EncryptedMessageTx.apply _)

}
