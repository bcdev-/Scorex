package scorex.serialization

import com.google.common.primitives.{Ints, Shorts}

trait BytesSerializable extends Serializable {

  def bytes: Array[Byte]

  protected def arrayWithSize(b: Array[Byte]): Array[Byte] = Ints.toByteArray(b.length) ++ b

  protected def arrayWithSize16bit(b: Array[Byte]): Array[Byte] = Shorts.toByteArray(b.length.toShort) ++ b
}
