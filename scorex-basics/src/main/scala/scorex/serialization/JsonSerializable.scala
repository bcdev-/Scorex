package scorex.serialization

import play.api.libs.json.JsObject
import scorex.wallet.Wallet

trait JsonSerializable {

  def json: JsObject

  // This function is executed when the API key is specified. It decrypts messages automatically.
  def jsonWithWallet(wallet: Wallet): JsObject = json
}
