package scorex.serialization

import java.net.InetSocketAddress

import org.scalacheck.Prop.{False, True}
import org.scalatest._
import org.scalatest.prop.PropertyChecks

import scala.util.{Success, Try}

class DeserSpecification extends PropSpec with PropertyChecks with Matchers with Deser[Int] with BytesSerializable {

  override def parseBytes(bytes: Array[Byte]): Try[Int] = Success(1)

  override def bytes = Array[Byte]()

  property("Deser parseFlags") {
    val bytes = Array[Byte](79, 1, -128, -127, -81)
    parseFlags(bytes, 0) shouldEqual (false, true, false, false, true, true, true, true, 1)
    parseFlags(bytes, 1) shouldEqual (false, false, false, false, false, false, false, true, 2)
    parseFlags(bytes, 2) shouldEqual (true, false, false, false, false, false, false, false, 3)
    parseFlags(bytes, 3) shouldEqual (true, false, false, false, false, false, false, true, 4)
    parseFlags(bytes, 4) shouldEqual (true, false, true, false, true, true, true, true, 5)
  }

  property("BytesSerializable flags") {
    parseFlags(flags(false, true, false, false, true, true, false, false), 0) shouldEqual
      (false, true, false, false, true, true, false, false, 1)
    parseFlags(flags(true, true, true, true, false, false, false, true), 0) shouldEqual
      (true, true, true, true, false, false, false, true, 1)
    parseFlags(flags(true, false, true), 0) shouldEqual
      (true, false, true, false, false, false, false, false, 1)
  }

}
