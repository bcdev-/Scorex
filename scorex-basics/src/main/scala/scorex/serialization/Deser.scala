package scorex.serialization

import com.google.common.primitives.Ints
import scorex.crypto.EllipticCurveImpl._

import scala.util.Try

/**
  * Interface for objects, that can deserialize bytes to instance of T
  */
trait Deser[T] {

  def parseBytes(bytes: Array[Byte]): Try[T]

  protected def parseArraySize(bytes: Array[Byte], position: Int): (Array[Byte], Int) = {
    val length = Ints.fromByteArray(bytes.slice(position, position + 4))
    (bytes.slice(position + 4, position + 4 + length), position + 4 + length)
  }

  protected def parseFlags(bytes: Array[Byte], position: Int): (Boolean, Boolean, Boolean, Boolean, Boolean,Boolean,
    Boolean, Boolean, Int) = {
    val b = bytes.apply(position)
    ((b & 128) != 0, (b & 64) != 0, (b & 32) != 0, (b & 16) != 0, (b & 8) != 0,
      (b & 4) != 0, (b & 2) != 0, (b & 1) != 0, position + 1)
  }

  protected def parseOption(bytes: Array[Byte], position: Int, length: Int): (Option[Array[Byte]], Int) = {
    if (bytes.slice(position, position + 1).head == (1: Byte)) {
      val b = bytes.slice(position + 1, position + 1 + length)
      (Some(b), position + 1 + length)
    } else (None, position + 1)
  }

}
