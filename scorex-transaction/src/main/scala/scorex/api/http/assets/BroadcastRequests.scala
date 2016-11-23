package scorex.api.http.assets

import com.google.common.base.Charsets
import io.swagger.annotations._
import play.api.libs.json._
import play.api.libs.functional.syntax._
import scorex.account.{Account, PublicKeyAccount}
import scorex.crypto.encode.Base58
import scorex.transaction.assets.{IssueTransaction, ReissueTransaction, TransferTransaction}

import scala.util.Try

object BroadcastRequests {

  @ApiModel(value = "Signed Asset issue transaction")
  case class AssetIssueRequest(@ApiModelProperty(value = "Base58 encoded Issuer public key", required = true)
                               senderPublicKey: String,
                               @ApiModelProperty(value = "Base58 encoded name of Asset", required = true)
                               name: String,
                               @ApiModelProperty(value = "Base58 encoded description of Asset", required = true)
                               description: String,
                               @ApiModelProperty(required = true, example = "1000000")
                               quantity: Long,
                               @ApiModelProperty(allowableValues = "range[0,8]", example = "8", dataType = "integer", required = true)
                               decimals: Byte,
                               @ApiModelProperty(required = true)
                               reissuable: Boolean,
                               @ApiModelProperty(required = true)
                               fee: Long,
                               @ApiModelProperty(required = true)
                               timestamp: Long,
                               @ApiModelProperty(required = true)
                               signature: String) {

    def toTx: Try[IssueTransaction] = Try {
      require(signature.length <= Account.Base58MaxSignatureLength, "signature is invalid")
      require(senderPublicKey.length <= Account.Base58MaxSenderPublicKeyLength, "sender public key is invalid")
      IssueTransaction(
        new PublicKeyAccount(Base58.decode(senderPublicKey).get),
        name.getBytes(Charsets.UTF_8),
        description.getBytes(Charsets.UTF_8),
        quantity,
        decimals,
        reissuable,
        fee,
        timestamp,
        Base58.decode(signature).get
      )
    }
  }


  case class AssetReissueRequest(@ApiModelProperty(value = "Base58 encoded Issuer public key", required = true)
                                 senderPublicKey: String,
                                 @ApiModelProperty(value = "Base58 encoded Asset ID", required = true)
                                 assetId: String,
                                 @ApiModelProperty(required = true, example = "1000000")
                                 quantity: Long,
                                 @ApiModelProperty(required = true)
                                 reissuable: Boolean,
                                 @ApiModelProperty(required = true)
                                 fee: Long,
                                 @ApiModelProperty(required = true)
                                 timestamp: Long,
                                 @ApiModelProperty(required = true)
                                 signature: String) {

    def toTx: Try[ReissueTransaction] = Try {
      require(signature.length <= Account.Base58MaxSignatureLength, "signature is invalid")
      require(senderPublicKey.length <= Account.Base58MaxSenderPublicKeyLength, "sender public key is invalid")
      require(assetId.length <= Account.Base58MaxTransactionIdLength, "asset ID is invalid")
      ReissueTransaction(
        new PublicKeyAccount(Base58.decode(senderPublicKey).get),
        Base58.decode(assetId).get,
        quantity,
        reissuable,
        fee,
        timestamp,
        Base58.decode(signature).get)
    }
  }

  @ApiModel(value = "Signed Asset transfer transaction")
  case class AssetTransferRequest(@ApiModelProperty(value = "Base58 encoded sender public key", required = true)
                                  senderPublicKey: String,
                                  @ApiModelProperty(value = "Base58 encoded Asset ID")
                                  assetId: Option[String],
                                  @ApiModelProperty(value = "Recipient address", required = true)
                                  recipient: String,
                                  @ApiModelProperty(required = true, example = "1000000")
                                  amount: Long,
                                  @ApiModelProperty(required = true)
                                  fee: Long,
                                  @ApiModelProperty(value = "Fee asset ID")
                                  feeAsset: Option[String],
                                  @ApiModelProperty(required = true)
                                  timestamp: Long,
                                  @ApiModelProperty(value = "Base58 encoded attachment")
                                  attachment: Option[String],
                                  @ApiModelProperty(required = true)
                                  signature: String) {
    def toTx: Try[TransferTransaction] = Try {
      require(signature.length <= Account.Base58MaxSignatureLength, "signature is invalid")
      require(senderPublicKey.length <= Account.Base58MaxSenderPublicKeyLength, "sender public key is invalid")
      if(assetId.isDefined)
        require(assetId.get.length <= Account.Base58MaxTransactionIdLength, "asset ID is invalid")
      if(attachment.isDefined)
        require(attachment.get.length <= TransferTransaction.MaxAttachmentSize * 2, "attachment is too long")
      TransferTransaction(
        assetId.map(Base58.decode(_).get),
        new PublicKeyAccount(Base58.decode(senderPublicKey).get),
        new Account(recipient),
        amount,
        timestamp,
        feeAsset.map(_.getBytes),
        fee,
        attachment.map(Base58.decode(_).get).getOrElse(new Array[Byte](0)),
        Base58.decode(signature).get)
    }
  }

  implicit val assetTransferRequestReads: Reads[AssetTransferRequest] = (
    (JsPath \ "senderPublicKey").read[String] and
      (JsPath \ "assetId").readNullable[String] and
      (JsPath \ "recipient").read[String] and
      (JsPath \ "amount").read[Long] and
      (JsPath \ "fee").read[Long] and
      (JsPath \ "feeAsset").readNullable[String] and
      (JsPath \ "timestamp").read[Long] and
      (JsPath \ "attachment").readNullable[String] and
      (JsPath \ "signature").read[String]
    ) (AssetTransferRequest.apply _)

  implicit val assetIssueRequestReads: Reads[AssetIssueRequest] = (
    (JsPath \ "senderPublicKey").read[String] and
      (JsPath \ "name").read[String] and
      (JsPath \ "description").read[String] and
      (JsPath \ "quantity").read[Long] and
      (JsPath \ "decimals").read[Byte] and
      (JsPath \ "reissuable").read[Boolean] and
      (JsPath \ "fee").read[Long] and
      (JsPath \ "timestamp").read[Long] and
      (JsPath \ "signature").read[String]
    ) (AssetIssueRequest.apply _)

  implicit val assetReissueRequestReads: Reads[AssetReissueRequest] = (
    (JsPath \ "senderPublicKey").read[String] and
      (JsPath \ "assetId").read[String] and
      (JsPath \ "quantity").read[Long] and
      (JsPath \ "reissuable").read[Boolean] and
      (JsPath \ "fee").read[Long] and
      (JsPath \ "timestamp").read[Long] and
      (JsPath \ "signature").read[String]
    ) (AssetReissueRequest.apply _)
}

