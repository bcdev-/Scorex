package scorex.consensus.mining

import akka.actor._
import scorex.app.Application
import scorex.network.peer.PeerManager.{ConnectedPeers, GetConnectedPeersTyped}
import scorex.utils.ScorexLogging

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import scala.language.postfixOps

class BlockGeneratorController(application: Application) extends Actor with ScorexLogging {

  import Application.GetBlockGenerationStatus
  import BlockGeneratorController._
  import Miner.{GuessABlock, Stop}

  private var workers: Seq[ActorRef] = Seq.empty

  context.system.scheduler.schedule(SelfCheckInterval, SelfCheckInterval, self, SelfCheck)

  override val supervisorStrategy = SupervisorStrategy.stoppingStrategy

  override def receive: Receive = idle

  def idle: Receive = state {

    case GetBlockGenerationStatus => sender() ! Idle.name

    case StartGeneration =>
      log.info("Start block generation")
      context.become(generating())
      self ! SelfCheck

    case StopGeneration =>

    case SelfCheck => stopWorkers()

    case ConnectedPeers(_) =>

    case LastBlockChanged =>
  }

  def generating(active: Boolean = true): Receive = state {

    case GetBlockGenerationStatus => sender() ! (if (active) Generating else Suspended).name

    case StartGeneration => if (active) self ! SelfCheck

    case SelfCheck => askForConnectedPeers()

    case StopGeneration =>
      log.info(s"Stop block generation")
      context.become(idle)
      stopWorkers()

    case ConnectedPeers(peers) => changeStateAccordingTo(peers.size, active)

    case LastBlockChanged =>
      if (active) {
        log.info(s"Enforce miners to generate block: $workers")
        workers.foreach { _ ! GuessABlock(rescheduleImmediately = true) }
      }
  }

  private def changeStateAccordingTo(peersNumber: Int, active: Boolean): Unit =
    if (peersNumber >= application.settings.quorum || application.settings.offlineGeneration) {
      startWorkers()
      if (!active) {
        log.info(s"Resume block generation")
        context become generating(active = true)
      }
    } else {
      stopWorkers()
      if (active) {
        log.info(s"Suspend block generation")
        context become generating(active = false)
      }
    }

  private def startWorkers() = {
    log.info(s"Check ${workers.size} miners")
    val threads = application.settings.miningThreads
    if (threads - workers.size > 0) workers = workers ++ newWorkers(threads - workers.size)
    workers.foreach { _ ! GuessABlock(false) }
  }

  private def stopWorkers() = if (workers.nonEmpty) {
    log.info(s"Stop miners: $workers vs ${context.children}")
    workers.foreach(_ ! Stop)
  }

  private def state(logic: Receive): Receive =
    logic orElse {
      case Terminated(worker) =>
        log.info(s"Miner terminated $worker")
        workers = workers.filter(_ != worker)

      case m => log.info(s"Unhandled $m")
    }

  private def newWorkers(count: Int): Seq[ActorRef] =  1 to count map { i =>
    context.watch(context.actorOf(Props(classOf[Miner], application), s"Worker-${System.currentTimeMillis()}-$i"))
  }

  private def askForConnectedPeers() = application.peerManager ! GetConnectedPeersTyped
}

object BlockGeneratorController {

  sealed trait Status {
    val name: String
  }

  case object Idle extends Status {
    override val name = "idle"
  }

  case object Generating extends Status {
    override val name = "generating"
  }

  case object Suspended extends Status {
    override val name = "suspended"
  }

  case object StartGeneration

  case object StopGeneration

  case object LastBlockChanged

  private[mining] case object SelfCheck

  private val SelfCheckInterval = 5 seconds
}
