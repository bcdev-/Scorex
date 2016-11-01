package scorex.lagonaki.integration.api

import org.scalatest.{FunSuite, Matchers}
import scorex.lagonaki.TestingCommons
import scorex.lagonaki.integration.TestLock

class AssetsAPISpecification extends FunSuite with TestLock with Matchers {

  import TestingCommons._

  override protected def beforeAll(): Unit = {
    super.beforeAll()

    if (wallet.privateKeyAccounts().size < 10) wallet.generateNewAccounts(10)
  }

  def wallet = application.wallet
  def account = accounts.head
  def address = account.address

  test("/assets/transfer Base58 non-UTF8 attachment") {
    val sender = accounts.head.address
    val recipient = accounts.last.address
//    val attachment = "4\\u00ff\\u00ea\\u0000\\u0089\\u0033\\u00ee\\u00ff\\u00ab\\u00c2\\u0002\\u0055\\u0043\\u00af"
    val attachment = "4\\u00ff\\u00ea\\u0000"

    val json = "{\"recipient\": \"" + recipient + "\",\n  \"assetIdOpt\": null,\n  \"feeAsset\": null,\n  \"feeAmount\": 1000000,\n  \"amount\": 42,\n  \"attachment\": \"" + attachment + "\",\n  \"sender\": \"" + sender + "\"\n}"
    val req = POST.request("/assets/transfer", body = json)
    println(req)

    (req \ "type").as[Int] shouldBe 4
    (req \ "recipient").as[String] shouldBe recipient
    (req \ "sender").as[String] shouldBe sender
    (req \ "timestamp").asOpt[Long].isDefined shouldBe true
    (req \ "signature").asOpt[String].isDefined shouldBe true
    (req \ "assetIdOpt").asOpt[String] shouldBe None
    (req \ "feeAsset").asOpt[String] shouldBe None
    (req \ "fee").as[Long] shouldBe 1000000
    (req \ "amount").as[Long] shouldBe 42

//    val result = new String(Array[Byte](52, -1, -22, 0, -119, 51, -18, -1, -85, -62, 2, 85, 67, -81))
    val result = new String(Array[Byte](52, -1, -22, 0))
    println((req \ "attachment").as[String].length)
    println((req \ "attachment").as[String])


    (req \ "attachment").as[String] shouldBe result


    application
  }

  def accounts = wallet.privateKeyAccounts()

  def addresses = accounts.map(_.address)

}