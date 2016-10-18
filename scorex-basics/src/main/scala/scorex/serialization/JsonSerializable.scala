package scorex.serialization

import play.api.libs.json.JsObject
import scorex.wallet.Wallet

trait JsonSerializable {

  def json: JsObject

  // This function is executed when the API key is specified. It makes all messages that can be read with
  // the private key decrypted.
  def jsonWithWallet(wallet: Wallet): JsObject = json
}
