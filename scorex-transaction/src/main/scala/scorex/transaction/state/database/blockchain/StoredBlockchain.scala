package scorex.transaction.state.database.blockchain

import org.h2.mvstore.{MVMap, MVStore}
import scorex.account.Account
import scorex.block.Block
import scorex.block.Block.BlockId
import scorex.consensus.ConsensusModule
import scorex.transaction.BlockStorage._
import scorex.transaction.History.BlockchainScore
import scorex.transaction.{BlockChain, TransactionModule}
import scorex.utils.{LogMVMapBuilder, ScorexLogging}
import scala.collection.JavaConversions._
import scala.collection.concurrent.TrieMap
import scala.util.control.NonFatal
import scala.util.{Failure, Success, Try}

/**
  * If no datafolder provided, blockchain lives in RAM (useful for tests)
  */
class StoredBlockchain(db: MVStore)
                      (implicit consensusModule: ConsensusModule[_],
                       transactionModule: TransactionModule[_])
  extends BlockChain with ScorexLogging {

  require(consensusModule != null)

  case class BlockchainPersistence(database: MVStore) {
    val blocks: MVMap[Int, Array[Byte]] = database.openMap("blocks", new LogMVMapBuilder[Int, Array[Byte]])
    val signatures: MVMap[Int, BlockId] = database.openMap("signatures", new LogMVMapBuilder[Int, BlockId])
    val signaturesReverse: MVMap[BlockId, Int] = database.openMap("signaturesReverse", new LogMVMapBuilder[BlockId, Int])
    private val BlocksCacheSizeLimit: Int = 1000
    private var blocksCacheSize: Int = 0
    private val blocksCache: TrieMap[Int, Option[Block]] = TrieMap.empty

    //TODO: remove when no blockchains without signaturesReverse remains
    if (signaturesReverse.size() != signatures.size()) {
      signaturesReverse.clear()
      signatures.keySet().foreach(k => signaturesReverse.put(signatures.get(k), k))
      database.commit()
    }

    val scoreMap: MVMap[Int, BigInt] = database.openMap("score", new LogMVMapBuilder[Int, BigInt])

    //if there are some uncommitted changes from last run, discard'em
    if (signatures.size() > 0) database.rollback()

    def writeBlock(height: Int, block: Block): Try[Unit] = Try {
      blocks.put(height, block.bytes)
      val blockScore = consensusModule.blockScore(block)
      scoreMap.put(height, ConsensusModule.cumulativeBlockScore(score(), blockScore))
      signatures.put(height, block.uniqueId)
      signaturesReverse.put(block.uniqueId, height)
    }

    def readBlock(height: Int): Option[Block] = {
      if (blocksCacheSize > BlocksCacheSizeLimit) {
        blocksCacheSize = 0
        blocksCache.clear()
      } else {
        blocksCacheSize = blocksCacheSize + 1
      }
      blocksCache.getOrElseUpdate(height,
        Try(Option(blocks.get(height))).toOption.flatten.flatMap(b => Block.parseBytes(b).recoverWith {
          case t: Throwable =>
            log.error("Block.parseBytes error", t)
            Failure(t)
        }.toOption))
    }

    def deleteBlock(height: Int): Unit = {
      blocksCache.remove(height)
      blocks.remove(height)
      val vOpt = Option(signatures.remove(height))
      vOpt.map(v => signaturesReverse.remove(v))
    }

    def contains(id: BlockId): Boolean = Option(signaturesReverse.get(id)).isDefined

    def height(): Int = signatures.size()

    def heightOf(id: BlockId): Option[Int] = Option(signaturesReverse.get(id))

    def score(): BlockchainScore = if (height() > 0) scoreMap.get(height()) else 0

    def score(id: BlockId): BlockchainScore = heightOf(id).map(scoreMap.get(_)).getOrElse(0)
  }

  private val blockStorage: BlockchainPersistence = BlockchainPersistence(db)

  override def appendBlock(block: Block): Try[BlocksToProcess] = synchronized {
    Try {
      val parent = block.referenceField
      if ((height() == 0) || (lastBlock.uniqueId sameElements parent.value)) {
        val h = height() + 1
        blockStorage.writeBlock(h, block) match {
          case Success(_) => Seq(block)
          case Failure(e) => throw new Error("Error while storing blockchain a change: " + e, e)
        }
      } else {
        throw new Error(s"Appending block ${block.json} which parent is not last block in blockchain")
      }
    }
  }

  override private[transaction] def discardBlock(): BlockChain = synchronized {
    require(height() > 1, "Chain is empty or contains genesis block only, can't make rollback")
    val h = height()
    blockStorage.deleteBlock(h)
    this
  }

  override def blockAt(height: Int): Option[Block] = synchronized {
    blockStorage.readBlock(height)
  }

  override def lastBlockIds(howMany: Int): Seq[BlockId] =
    (Math.max(1, height() - howMany + 1) to height()).flatMap(i => Option(blockStorage.signatures.get(i)))
      .reverse

  override def contains(signature: Array[Byte]): Boolean = blockStorage.contains(signature)

  override def height(): Int = blockStorage.height()

  override def score(): BlockchainScore = blockStorage.score()

  override def scoreOf(id: BlockId): BlockchainScore = blockStorage.score(id)

  override def heightOf(blockSignature: Array[Byte]): Option[Int] = blockStorage.heightOf(blockSignature)

  override def blockById(blockId: BlockId): Option[Block] = heightOf(blockId).flatMap(blockAt)

  override def children(block: Block): Seq[Block] = heightOf(block).flatMap(h => blockAt(h + 1)).toSeq

  override def generatedBy(account: Account, from: Int, to: Int): Seq[Block] = {
    (from to to).toStream.flatMap { h =>
      blockAt(h).flatMap { block =>
        if (consensusModule.generators(block).contains(account)) Some(block) else None
      }
    }
  }

  override def toString: String = ((1 to height()) map { h =>
    val bl = blockAt(h).get
    s"$h -- ${bl.uniqueId.mkString} -- ${bl.referenceField.value.mkString }"
  }).mkString("\n")
}
