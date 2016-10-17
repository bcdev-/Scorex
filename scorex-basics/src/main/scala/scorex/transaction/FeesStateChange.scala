package scorex.transaction

import com.google.common.primitives.Longs

@SerialVersionUID(-8850164212397152939L)
case class FeesStateChange(fee: Long) extends StateChangeReason {
  override def bytes: Array[Byte] = Longs.toByteArray(fee)

  override val id: Array[Byte] = Array.empty
}
