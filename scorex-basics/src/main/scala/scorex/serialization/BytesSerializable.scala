package scorex.serialization

import com.google.common.primitives.Ints

trait BytesSerializable extends Serializable {

  def bytes: Array[Byte]

  protected def arrayWithSize(b: Array[Byte]): Array[Byte] = Ints.toByteArray(b.length) ++ b

  protected def flags(b0: Boolean, b1: Boolean = false, b2: Boolean = false, b3: Boolean = false, b4: Boolean = false,
                      b5: Boolean = false, b6: Boolean = false, b7: Boolean = false): Array[Byte] = {
    implicit def b2i(b: Boolean) = if (b) 1 else 0
    Array[Byte]((b0 * 128 + b1 * 64 + b2 * 32 + b3 * 16 + b4 * 8 + b5 * 4 + b6 * 2 + b7).toByte)
  }
}
