package scorex.transaction.state.wallet

import play.api.libs.functional.syntax._
import play.api.libs.json.{JsPath, Reads, Writes}

case class MessageTx(fee: Long, sender: String, recipient: String, message: String)

object MessageTx {
  implicit val messageWrites: Writes[MessageTx] = (
    (JsPath \ "fee").write[Long] and
      (JsPath \ "sender").write[String] and
      (JsPath \ "recipient").write[String] and
      (JsPath \ "message").write[String]
    ) (unlift(MessageTx.unapply))

  implicit val messageReads: Reads[MessageTx] = (
    (JsPath \ "fee").read[Long] and
      (JsPath \ "sender").read[String] and
      (JsPath \ "recipient").read[String] and
      (JsPath \ "message").read[String]
    ) (MessageTx.apply _)

}
