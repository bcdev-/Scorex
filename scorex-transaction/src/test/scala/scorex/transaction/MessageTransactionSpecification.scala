package scorex.transaction

import org.scalatest._
import org.scalatest.prop.PropertyChecks

class MessageTransactionSpecification extends PropSpec with PropertyChecks with Matchers with TransactionGen {

  property("MessageTransaction serialization roundtrip") {
    forAll(messageGenerator) { issue: MessageTransaction =>
      val recovered = MessageTransaction.parseBytes(issue.bytes).get
      issue.validate shouldEqual ValidationResult.ValidateOke
      recovered.validate shouldEqual ValidationResult.ValidateOke
      recovered.bytes shouldEqual issue.bytes
      issue.message shouldEqual recovered.message
      issue.messageHash shouldEqual recovered.messageHash
    }
  }

  property("MessageTransaction serialization from TypedTransaction") {
    forAll(messageGenerator) { issue: MessageTransaction =>
      val recovered = TypedTransaction.parseBytes(issue.bytes).get
      issue.validate shouldEqual ValidationResult.ValidateOke
      recovered.bytes shouldEqual issue.bytes
      issue.messageHash shouldEqual recovered.asInstanceOf[MessageTransaction].messageHash
    }
  }

  property("MessageTransaction validation fail") {
    forAll(invalidMessageGenerator) { issue: MessageTransaction =>
      val recovered = MessageTransaction.parseBytes(issue.bytes).get
      issue.validate should not equal ValidationResult.ValidateOke
      recovered.bytes shouldEqual issue.bytes
      issue.messageHash shouldEqual recovered.messageHash
    }
  }

}
