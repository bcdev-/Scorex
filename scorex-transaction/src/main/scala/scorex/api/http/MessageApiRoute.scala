package scorex.api.http

import javax.ws.rs.Path

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server.Route
import io.swagger.annotations._
import play.api.libs.json.{JsError, JsSuccess, Json}
import scorex.transaction._
import scorex.transaction.state.wallet.{EncryptedMessageTx, MessageTx}

import scala.util.{Failure, Success, Try}
import akka.actor.ActorRefFactory
import io.swagger.annotations.{ApiImplicitParam, ApiImplicitParams, ApiOperation}
import scorex.app.RunnableApplication

@Path("/message")
@Api(value = "/message")
case class MessageApiRoute(application: RunnableApplication)(implicit val context: ActorRefFactory)
  extends ApiRoute with CommonTransactionApiFunctions {
  val settings = application.settings
  lazy val wallet = application.wallet

  override lazy val route = pathPrefix("message") {
    sendMessage ~ sendEncryptedMessage
  }
  private implicit val transactionModule = application.transactionModule.asInstanceOf[SimpleTransactionModule]

  @Path("/send")
  @ApiOperation(value = "Send message",
    notes = "Send a message through the blockchain",
    httpMethod = "POST",
    produces = "application/json",
    consumes = "application/json")
  @ApiImplicitParams(Array(
    new ApiImplicitParam(
      name = "body",
      value = "Json with data",
      required = true,
      paramType = "body",
      dataType = "scorex.transaction.state.wallet.MessageTx",
      defaultValue = "{\n\t\"message\":\"Message to send\",\n\t\"fee\":10000,\n\t\"sender\":\"senderId\",\n\t\"recipient\":\"recipientId\"\n}"
    )
  ))
  @ApiResponses(Array(
    new ApiResponse(code = 200, message = "Json with response or error")
  ))
  def sendMessage: Route = path("send") {
    entity(as[String]) { body =>
      withAuth {
        postJsonRoute {
          walletNotExists(wallet).getOrElse {
            Try(Json.parse(body)).map { js =>
              js.validate[MessageTx] match {
                case err: JsError =>
                  WrongTransactionJson(err).response
                case JsSuccess(message: MessageTx, _) =>
                  val txOpt: Try[MessageTransaction] = transactionModule.sendMessage(message, wallet)
                  txOpt match {
                    case Success(tx) =>
                      JsonResponse(tx.json, StatusCodes.OK)
                    case Failure(e: StateCheckFailed) =>
                      StateCheckFailed.response
                    case _ =>
                      WrongJson.response
                  }
              }
            }.getOrElse(WrongJson.response)
          }
        }
      }
    }
  }


  @Path("/send-encrypted")
  @ApiOperation(value = "Send encrypted message",
    notes = "Send an encrypted message through the blockchain",
    httpMethod = "POST",
    produces = "application/json",
    consumes = "application/json")
  @ApiImplicitParams(Array(
    new ApiImplicitParam(
      name = "body",
      value = "Json with data",
      required = true,
      paramType = "body",
      dataType = "scorex.transaction.state.wallet.EncryptedMessageTx",
      defaultValue = "{\n\t\"message\":\"Message to send\",\n\t\"fee\":10000,\n\t\"sender\":\"senderId\",\n\t\"recipientPublicKey\":\"recipientId\"\n}"
    )
  ))
  @ApiResponses(Array(
    new ApiResponse(code = 200, message = "Json with response or error")
  ))
  def sendEncryptedMessage: Route = path("send-encrypted") {
    entity(as[String]) { body =>
      withAuth {
        postJsonRoute {
          walletNotExists(wallet).getOrElse {
            Try(Json.parse(body)).map { js =>
              js.validate[EncryptedMessageTx] match {
                case err: JsError =>
                  WrongTransactionJson(err).response
                case JsSuccess(message: EncryptedMessageTx, _) =>
                  val txOpt: Try[EncryptedMessageTransaction] = transactionModule.sendEncryptedMessage(message, wallet)
                  txOpt match {
                    case Success(tx) =>
                      JsonResponse(tx.jsonWithWallet(wallet), StatusCodes.OK)
                    case Failure(e: StateCheckFailed) =>
                      StateCheckFailed.response
                    case _ =>
                      WrongJson.response
                  }
              }
            }.getOrElse(WrongJson.response)
          }
        }
      }
    }
  }
}
