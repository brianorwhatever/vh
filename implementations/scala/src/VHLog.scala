package vhlog

import ujson.*
import java.nio.charset.StandardCharsets.UTF_8
import java.security.*
import java.security.spec.*
import java.time.*
import java.math.{BigDecimal as Decimal, MathContext, RoundingMode}

/** Native Scala controller and resolver. JSON numbers are always binary64. */
object VHLog {
  private val alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  final case class ProtocolError(
      code: String,
      version: Value = Null,
      fork: Value = Null
  ) extends RuntimeException(code) {
    def report: Value = {
      val r =
        Obj("code" -> Str(code), "version" -> version, "message" -> Str(code))
      if (fork != Null) r("fork") = fork
      r
    }
  }
  private def fail(code: String, n: Int = 0, fork: Value = Null): Nothing =
    throw ProtocolError(code, if (n == 0) Null else Num(n), fork)
  private def get(v: Value, k: String): Value =
    v.objOpt.flatMap(_.get(k)).getOrElse(Null)
  private def has(v: Value, k: String): Boolean = v.objOpt.exists(_.contains(k))
  private def default(v: Value, k: String, d: => Value): Value =
    if (has(v, k)) v(k) else d
  private def obj(v: Value): Boolean = v.isInstanceOf[Obj]
  private def arr(v: Value): Boolean = v.isInstanceOf[Arr]
  private def string(v: Value): Boolean = v.isInstanceOf[Str]
  private def integer(v: Value): Boolean =
    v.numOpt.exists(d => d.isFinite && d == math.floor(d))
  private def strings(v: Value): Boolean = v.arrOpt.exists(_.forall(string))
  private def copy(v: Value): Obj = Obj.from(v.obj.toSeq)
  private def without(v: Value, key: String): Obj =
    Obj.from(v.obj.toSeq.filter(_._1 != key))
  private def validUnicode(s: String): Unit = {
    var i = 0
    while (i < s.length) {
      val c = s.charAt(i)
      if (Character.isHighSurrogate(c)) {
        i += 1
        require(
          i < s.length && Character.isLowSurrogate(s.charAt(i)),
          "lone surrogate"
        )
      } else require(!Character.isLowSurrogate(c), "lone surrogate")
      i += 1
    }
  }
  def parse(s: String): Value = {
    val v = ujson.read(s)
    def check(x: Value): Unit = x match {
      case Num(d) => require(d.isFinite, "non-finite number")
      case Str(s) => validUnicode(s)
      case a: Arr => a.value.foreach(check)
      case o: Obj =>
        o.value.foreach { case (k, v) => validUnicode(k); check(v) }
      case _ => ()
    }
    check(v); v
  }
  def number(d: Double): String = {
    require(d.isFinite, "non-finite number")
    if (d == 0) return "0"
    val exact = new Decimal(math.abs(d))
    val rounded = (1 to 17).iterator
      .map(p => exact.round(new MathContext(p, RoundingMode.HALF_EVEN)))
      .find(_.doubleValue == math.abs(d))
      .get
      .stripTrailingZeros
    val digits = rounded.unscaledValue.toString
    val n = digits.length - rounded.scale
    val body =
      if (n >= digits.length && n <= 21) digits + "0" * (n - digits.length)
      else if (n > 0 && n <= 21) digits.take(n) + "." + digits.drop(n)
      else if (n <= 0 && n > -6) "0." + "0" * (-n) + digits
      else
        digits.take(1) + (if (digits.length > 1) "." + digits.drop(1)
                          else
                            "") + "e" + (if (n - 1 >= 0) "+" else "") + (n - 1)
    (if (d < 0) "-" else "") + body
  }
  def jcs(v: Value): String = v match {
    case o: Obj =>
      o.value.keys.toSeq.sorted
        .map(k => jcs(Str(k)) + ":" + jcs(o(k)))
        .mkString("{", ",", "}")
    case a: Arr => a.value.map(jcs).mkString("[", ",", "]")
    case Num(d) => number(d)
    case Str(s) =>
      validUnicode(s)
      val b = new StringBuilder("\"")
      s.foreach {
        case '"'         => b.append("\\\"")
        case '\\'        => b.append("\\\\")
        case '\b'        => b.append("\\b")
        case '\f'        => b.append("\\f")
        case '\n'        => b.append("\\n")
        case '\r'        => b.append("\\r")
        case '\t'        => b.append("\\t")
        case c if c < 32 => b.append(f"\\u${c.toInt}%04x")
        case c           => b.append(c)
      }
      b.append('"').toString
    case _ => v.toString
  }
  def encode(bytes: Array[Byte]): String = {
    var n = BigInt(1, bytes); var out = ""
    while (n > 0) { out = alphabet((n % 58).toInt) + out; n /= 58 }
    "1" * bytes.takeWhile(_ == 0).length + out
  }
  def decode(v: Value): Option[Array[Byte]] = v.strOpt.flatMap { s =>
    if (!s.forall(alphabet.contains(_))) None
    else {
      val n = s.foldLeft(BigInt(0))((n, c) => n * 58 + alphabet.indexOf(c))
      val b =
        if (n == 0) Array.emptyByteArray else n.toByteArray.dropWhile(_ == 0)
      Some(Array.fill[Byte](s.takeWhile(_ == '1').length)(0) ++ b)
    }
  }
  def sha(s: String): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(s.getBytes(UTF_8))
  def hash(s: String): String = encode(Array[Byte](0x12, 0x20) ++ sha(s))
  private def checkHash(v: Value): String = decode(v) match {
    case None => "not-base58"
    case Some(b) if b.length == 34 && b(0) == 0x12 && b(1) == 0x20 => "ok"
    case _ => "unsupported-algorithm"
  }
  def publicKey(v: Value): Option[Array[Byte]] = v.strOpt
    .filter(_.startsWith("z"))
    .flatMap(s => decode(Str(s.drop(1))))
    .filter(b => b.length == 34 && b(0) == 0xed.toByte && b(1) == 1)
    .map(_.drop(2))
  private def signer(hex: String): KeyPair = {
    require(hex.matches("[0-9a-fA-F]{64}"), "seed must be 32-byte hex")
    val seed = java.util.HexFormat.of.parseHex(hex)
    val gen = KeyPairGenerator.getInstance("Ed25519")
    gen.initialize(
      NamedParameterSpec.ED25519,
      new SecureRandom {
        override def nextBytes(b: Array[Byte]): Unit = {
          require(b.length == 32); System.arraycopy(seed, 0, b, 0, 32)
        }
      }
    )
    gen.generateKeyPair()
  }
  def multikey(seed: String): String = "z" + encode(
    Array[Byte](0xed.toByte, 1) ++ signer(seed).getPublic.getEncoded
      .takeRight(32)
  )
  private def methodKey(v: Value): Option[String] =
    v.strOpt.filter(_.startsWith("did:key:")).flatMap { s =>
      val p = s.drop(8).split("#", -1)
      if (p.length == 2 && p(0) == p(1) && publicKey(Str(p(0))).isDefined)
        Some(p(0))
      else None
    }
  def signingInput(document: Value, config: Value): Array[Byte] =
    sha(jcs(config)) ++ sha(jcs(document))
  def sign(document: Value, seed: String, options: Value = Obj()): Value = {
    val mk = multikey(seed)
    val config = Obj(
      "type" -> "DataIntegrityProof",
      "cryptosuite" -> "eddsa-jcs-2022",
      "verificationMethod" -> default(
        options,
        "verificationMethod",
        Str(s"did:key:$mk#$mk")
      )
    )
    if (has(options, "created")) config("created") = options("created")
    config("proofPurpose") = Str("assertionMethod")
    val s = Signature.getInstance("Ed25519");
    s.initSign(signer(seed).getPrivate);
    s.update(signingInput(document, config))
    config("proofValue") = Str("z" + encode(s.sign())); config
  }
  def verify(document: Value, proof: Value): Boolean = {
    try {
      if (
        get(proof, "type") != Str("DataIntegrityProof") || get(
          proof,
          "cryptosuite"
        ) != Str("eddsa-jcs-2022") || get(proof, "proofPurpose") != Str(
          "assertionMethod"
        )
      ) return false
      val mk = methodKey(get(proof, "verificationMethod"))
      val sig = get(proof, "proofValue").strOpt
        .filter(_.startsWith("z"))
        .flatMap(s => decode(Str(s.drop(1))))
        .filter(_.length == 64)
      if (mk.isEmpty || sig.isEmpty) return false
      val der = java.util.HexFormat.of
        .parseHex("302a300506032b6570032100") ++ publicKey(Str(mk.get)).get
      val key = KeyFactory
        .getInstance("Ed25519")
        .generatePublic(new X509EncodedKeySpec(der))
      val s = Signature.getInstance("Ed25519"); s.initVerify(key);
      s.update(signingInput(document, without(proof, "proofValue")));
      s.verify(sig.get)
    } catch { case _: Exception => false }
  }
  def scid(e: Value): String = hash(jcs(without(e, "proof")))
  def entryHash(e: Value, previous: String): String = {
    val d = without(e, "proof"); d("versionId") = Str(previous); hash(jcs(d))
  }
  private def lines(log: String): Vector[String] = {
    val a = log.split("\n", -1).toVector
    if (a.last == "") a.dropRight(1) else a
  }
  def create(input: Value): Value = {
    val p = Obj("logVersion" -> "vh-log:1.0", "scid" -> "{SCID}");
    input("parameters").obj.foreach { case (k, v) => p(k) = v }
    var e: Value = Obj(
      "versionId" -> "{SCID}",
      "versionTime" -> input("versionTime"),
      "parameters" -> p,
      "state" -> input("state")
    )
    val id = scid(e); e = parse(jcs(e).replace("{SCID}", id));
    e("versionId") = Str("1-" + entryHash(e, id))
    val proofs = input("signers").arr.map(s =>
      sign(e, s.str, Obj("created" -> input("versionTime")))
    )
    e("proof") = Arr.from(proofs)
    Obj("log" -> (jcs(e) + "\n"), "scid" -> id, "versionId" -> e("versionId"))
  }
  def update(input: Value): Value = {
    val previous = parse(lines(input("log").str).last)("versionId").str
    val e = Obj(
      "versionId" -> previous,
      "versionTime" -> input("versionTime"),
      "parameters" -> default(input, "parameters", Obj()),
      "state" -> input("state")
    )
    e("versionId") = Str(
      (BigInt(previous.takeWhile(_ != '-')) + 1).toString + "-" + entryHash(
        e,
        previous
      )
    )
    val proofs = input("signers").arr.map(s =>
      sign(e, s.str, Obj("created" -> input("versionTime")))
    )
    e("proof") = Arr.from(proofs)
    val log = input("log").str
    Obj(
      "log" -> (log + (if (log.endsWith("\n")) "" else "\n") + jcs(e) + "\n"),
      "versionId" -> e("versionId")
    )
  }
  private def time(v: Value): Option[Long] = v.strOpt.flatMap { s =>
    if (
      !s.matches(
        "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|\\+00:00)"
      )
    ) None
    else
      try {
        Some(LocalDateTime.parse(s.take(19)).toEpochSecond(ZoneOffset.UTC))
      } catch { case _: Exception => None }
  }
  private def parameters(raw: Value, previous: Option[Value], n: Int): Value = {
    if (raw.obj.values.exists(_ == Null)) fail("invalid-parameter", n)
    if (
      (previous.isEmpty && !has(raw, "logVersion")) || (has(
        raw,
        "logVersion"
      ) && raw("logVersion") != Str("vh-log:1.0"))
    ) fail("unsupported-log-version", n)
    if (
      if (previous.isDefined) has(raw, "scid")
      else !string(get(raw, "scid")) || !has(raw, "updateKeys")
    ) fail("invalid-parameter", n)
    if (
      has(raw, "updateKeys") && (!strings(raw("updateKeys")) || !raw(
        "updateKeys"
      ).arr.forall(k => publicKey(k).isDefined))
    ) fail("invalid-parameter", n)
    if (
      has(raw, "nextKeyHashes") && (!strings(raw("nextKeyHashes")) || !raw(
        "nextKeyHashes"
      ).arr.forall(h => checkHash(h) == "ok"))
    ) fail("invalid-parameter", n)
    val p = copy(
      previous.getOrElse(
        Obj(
          "nextKeyHashes" -> Arr(),
          "witness" -> Null,
          "watchers" -> Arr(),
          "ttl" -> 3600
        )
      )
    )
    Seq(
      "logVersion",
      "scid",
      "updateKeys",
      "nextKeyHashes",
      "witness",
      "watchers",
      "ttl"
    ).foreach(k => if (has(raw, k)) p(k) = raw(k))
    p("deactivated") = default(raw, "deactivated", Bool(false))
    if (has(raw, "witness")) {
      val w = raw("witness")
      if (!obj(w)) fail("invalid-parameter", n)
      if (w.obj.isEmpty) p("witness") = Null
      else {
        val ws = get(w, "witnesses")
        if (
          !arr(ws) || ws.arr.isEmpty || !ws.arr.forall(x =>
            get(x, "id").strOpt.exists(s =>
              s.startsWith("did:key:") && publicKey(Str(s.drop(8))).isDefined
            )
          )
        ) fail("invalid-parameter", n)
        val ids = ws.arr.map(_("id").str)
        val threshold = get(w, "threshold")
        if (
          ids.distinct.size != ids.size || !integer(
            threshold
          ) || threshold.num < 1 || threshold.num > ids.size
        ) fail("invalid-parameter", n)
        p("witness") = Obj("threshold" -> threshold, "witnesses" -> ws)
      }
    }
    if (
      has(raw, "watchers") && (!strings(raw("watchers")) || !raw("watchers").arr
        .forall(u =>
          u.str.matches("[\\x21-\\x7e]+") && u.str.matches("https?://[^/?#].*")
        ))
    ) fail("invalid-parameter", n)
    if (
      !p("deactivated").isInstanceOf[Bool] || !integer(p("ttl")) || p(
        "ttl"
      ).num < 0 || p("ttl").num > 2147483648d
    ) fail("invalid-parameter", n)
    previous.filter(_("nextKeyHashes").arr.nonEmpty).foreach { old =>
      if (!has(raw, "updateKeys") || !has(raw, "nextKeyHashes"))
        fail("prerotation-violation", n)
      raw("updateKeys").arr.foreach(k =>
        if (!old("nextKeyHashes").arr.contains(Str(hash(k.str))))
          fail("prerotation-violation", n)
      )
    }
    p
  }
  private case class Entry(e: Value, p: Value, n: Int, time: Long, rule: Value)
  private case class Log(
      entries: Vector[Entry],
      lines: Vector[String],
      failure: Option[ProtocolError]
  )
  private def verifyEntry(
      e: Value,
      previous: Option[Entry],
      now: Long
  ): Entry = {
    val n = previous.map(_.n + 1).getOrElse(1)
    if (previous.exists(_.p("deactivated").bool))
      fail("entry-after-deactivation", n)
    if (
      e.obj.keySet.toSet != Set(
        "parameters",
        "proof",
        "state",
        "versionId",
        "versionTime"
      ) || !string(e("versionId")) || !string(e("versionTime")) || !obj(
        e("parameters")
      ) || !obj(e("state")) || !arr(e("proof"))
    ) fail("invalid-entry", n)
    val p = parameters(e("parameters"), previous.map(_.p), n)
    val keys =
      if (previous.isEmpty || previous.get.p("nextKeyHashes").arr.nonEmpty)
        p("updateKeys")
      else previous.get.p("updateKeys")
    val rule =
      if (
        previous.isEmpty || (has(e("parameters"), "witness") && previous.get.p(
          "witness"
        ) == Null)
      ) p("witness")
      else previous.get.p("witness")
    if (e("proof").arr.isEmpty) fail("invalid-proof", n)
    e("proof").arr.foreach { proof =>
      val mk = methodKey(get(proof, "verificationMethod")).getOrElse(
        fail("invalid-proof", n)
      )
      if (!keys.arr.contains(Str(mk))) fail("unauthorized-key", n)
      if (!verify(without(e, "proof"), proof)) fail("invalid-proof", n)
    }
    val pattern = "([1-9][0-9]*)-([^-]+)".r
    val hashPart = e("versionId").str match {
      case pattern(v, h) if BigInt(v) == n => h
      case _                               => fail("invalid-version-id", n)
    }
    val status = checkHash(Str(hashPart))
    if (status == "not-base58") fail("invalid-version-id", n)
    if (status != "ok") fail("invalid-hash-algorithm", n)
    if (
      entryHash(
        e,
        previous.map(_.e("versionId").str).getOrElse(p("scid").str)
      ) != hashPart
    ) fail("entry-hash-mismatch", n)
    val t = time(e("versionTime")).getOrElse(fail("invalid-version-time", n))
    if (previous.exists(_.time >= t)) fail("invalid-version-time", n)
    if (t > now + 300) fail("future-version-time", n)
    if (previous.isEmpty) {
      val status = checkHash(p("scid"))
      if (status == "unsupported-algorithm") fail("invalid-hash-algorithm", n)
      if (status != "ok") fail("scid-mismatch", n)
      val rest = without(e, "proof"); rest("versionId") = Str("{SCID}")
      val restored = parse(jcs(rest).replace(p("scid").str, "{SCID}"))
      if (scid(restored) != p("scid").str) fail("scid-mismatch", n)
    }
    Entry(e, p, n, t, rule)
  }
  private def verifyLog(log: String, witness: Option[Value], now: Long): Log = {
    val ls = lines(log); var entries = Vector.empty[Entry];
    var failure = Option.empty[ProtocolError]
    if (ls.isEmpty) return Log(entries, ls, Some(ProtocolError("invalid-log")))
    ls.zipWithIndex.iterator.takeWhile(_ => failure.isEmpty).foreach {
      case (line, i) =>
        try {
          val e = try { parse(line) }
          catch { case _: Exception => fail("invalid-log", i + 1) }
          if (!obj(e)) fail("invalid-log", i + 1)
          entries :+= verifyEntry(e, entries.lastOption, now)
        } catch { case error: ProtocolError => failure = Some(error) }
    }
    val verified = entries
    var stopped = false
    verified.zipWithIndex.iterator.takeWhile(_ => !stopped).foreach {
      case (e, i) =>
        if (e.rule != Null) {
          val file = witness.getOrElse(Arr())
          var code = Option.empty[String]
          if (
            !arr(file) || !file.arr.forall(r =>
              obj(r) && string(get(r, "versionId")) && arr(get(r, "proof"))
            )
          ) code = Some("invalid-witness-file")
          else {
            val allowed = e.rule("witnesses").arr.map(_("id").str).toSet
            val ids = scala.collection.mutable.Set.empty[String]
            file.arr.foreach { r =>
              val index =
                verified.indexWhere(_.e("versionId") == r("versionId"))
              if (index >= i) r("proof").arr.foreach { proof =>
                methodKey(get(proof, "verificationMethod")).foreach { mk =>
                  val id = "did:key:" + mk
                  if (
                    allowed(id) && verify(
                      Obj("versionId" -> r("versionId")),
                      proof
                    )
                  ) ids += id
                }
              }
            }
            if (ids.size < e.rule("threshold").num)
              code = Some("witness-threshold-not-met")
          }
          code.foreach { c =>
            failure = Some(ProtocolError(c, Num(i + 1)));
            entries = verified.take(i); stopped = true
          }
        }
    }
    Log(entries, ls, failure)
  }
  private def lineValue(line: String): Value = try parse(line)
  catch { case _: Exception => Null }
  private def lineId(line: String): Value = {
    val v = get(lineValue(line), "versionId"); if (string(v)) v else Null
  }
  private def retained(
      v: Log,
      source: String,
      id: Value,
      warnings: Arr
  ): Unit = {
    val pat = "^([1-9][0-9]*)-".r
    val n = id.strOpt
      .flatMap(s => pat.findFirstMatchIn(s))
      .map(m => BigInt(m.group(1)))
      .getOrElse(fail("invalid-option"))
    if (n > v.entries.size)
      warnings.value += Obj(
        "code" -> "retained-version-not-found",
        "message" -> "retained version not found"
      )
    else if (v.entries(n.toInt - 1).e("versionId") != id)
      fail(
        "fork-detected",
        n.toInt,
        Obj(
          "version" -> Num(n.toDouble),
          "copies" -> Arr(
            Obj("source" -> "retained", "versionId" -> id),
            Obj(
              "source" -> source,
              "versionId" -> v.entries(n.toInt - 1).e("versionId")
            )
          )
        )
      )
  }
  private def result(
      v: Log,
      options: Value,
      warnings: Arr,
      copies: Option[Value] = None
  ): Value = {
    var target = Option.empty[Entry]
    if (has(options, "versionId")) {
      target = v.entries.find(_.e("versionId") == options("versionId"))
      if (
        target.isEmpty && v.lines
          .drop(v.entries.size)
          .exists(lineId(_) == options("versionId"))
      ) throw v.failure.get
    } else if (has(options, "versionNumber")) {
      val n = options("versionNumber").num
      if (n <= v.entries.size) target = Some(v.entries(n.toInt - 1))
      if (target.isEmpty && n <= v.lines.size) throw v.failure.get
    } else if (has(options, "versionTime")) {
      val t = time(options("versionTime")).get
      if (
        v.failure.isDefined && time(
          get(lineValue(v.lines(v.entries.size)), "versionTime")
        ).exists(_ <= t)
      ) throw v.failure.get
      target = v.entries.reverse.find(_.time <= t)
    } else target = v.entries.lastOption
    val chosen = target.getOrElse(fail("not-found"));
    val first = v.entries.head; val last = v.entries.last
    v.failure.foreach(e =>
      warnings.value += Obj("code" -> "invalid-entries", "message" -> e.code)
    )
    val meta = Obj(
      "versionId" -> chosen.e("versionId"),
      "versionTime" -> chosen.e("versionTime"),
      "versionNumber" -> chosen.n,
      "created" -> first.e("versionTime"),
      "updated" -> last.e("versionTime"),
      "scid" -> first.p("scid"),
      "deactivated" -> last.p("deactivated"),
      "ttl" -> last.p("ttl"),
      "witness" -> last.p("witness"),
      "watchers" -> last.p("watchers"),
      "updateKeys" -> chosen.p("updateKeys"),
      "nextKeyHashes" -> chosen.p("nextKeyHashes"),
      "warnings" -> warnings
    )
    copies.foreach(c => meta("copies") = c)
    Obj(
      "valid" -> true,
      "state" -> chosen.e("state"),
      "metadata" -> meta,
      "firstInvalidVersion" -> v.failure
        .map(_ => Num(v.entries.size + 1))
        .getOrElse(Null),
      "error" -> v.failure.map(_.report).getOrElse(Null)
    )
  }
  private def resolveCopies(input: Value, now: Long, options: Value): Value = {
    val primary = Obj("source" -> "primary", "log" -> input("log"));
    if (has(input, "witness")) primary("witness") = input("witness")
    val all = Vector(primary) ++ default(input, "copies", Arr()).arr.toVector
    val warnings = Arr();
    val status = scala.collection.mutable.Map.empty[Int, String];
    val cache = scala.collection.mutable.Map.empty[Int, Log]
    def getLog(i: Int): Log = cache.getOrElseUpdate(
      i,
      verifyLog(all(i)("log").str, all(i).obj.get("witness"), now)
    )
    def invalid(i: Int): Unit = {
      status(i) = "invalid";
      warnings.value += Obj(
        "code" -> "copy-invalid",
        "source" -> all(i)("source"),
        "message" -> "copy fails verification"
      )
    }
    all.indices.foreach { i =>
      if (has(all(i), "unavailable")) {
        status(i) = "unavailable";
        warnings.value += Obj(
          "code" -> "copy-unavailable",
          "source" -> all(i)("source"),
          "message" -> all(i)("unavailable")
        )
      }
    }
    var ref = -1
    all.indices.iterator.takeWhile(_ => ref < 0).foreach { i =>
      if (!status.contains(i)) {
        if (getLog(i).failure.isEmpty) ref = i else invalid(i)
      }
    }
    if (ref < 0)
      return Obj("valid" -> false, "error" -> getLog(0).failure.get.report)
    val matched = scala.collection.mutable.Set(ref)
    all.indices.foreach { i =>
      if (!status.contains(i) && !matched(i)) {
        val r = getLog(ref); val c = getLog(i); val rl = r.lines;
        val cl = c.lines
        if (cl.isEmpty) invalid(i)
        else {
          val same = cl.size <= rl.size && lineId(cl.last) == r
            .entries(cl.size - 1)
            .e("versionId")
          val extendsLog = cl.size > rl.size && lineId(
            cl(rl.size - 1)
          ) == r.entries.last.e("versionId")
          if (same) matched += i
          else if (extendsLog && c.failure.isEmpty) { matched += i; ref = i }
          else if (c.failure.isDefined) invalid(i)
          else {
            val k = (0 until math.min(rl.size, cl.size))
              .find(j => lineId(rl(j)) != lineId(cl(j)))
              .getOrElse(math.min(rl.size, cl.size))
            fail(
              "fork-detected",
              k + 1,
              Obj(
                "version" -> (k + 1),
                "copies" -> Arr(
                  Obj(
                    "source" -> all(ref)("source"),
                    "versionId" -> rl.lift(k).map(lineId).getOrElse(Str(""))
                  ),
                  Obj(
                    "source" -> all(i)("source"),
                    "versionId" -> cl.lift(k).map(lineId).getOrElse(Str(""))
                  )
                )
              )
            )
          }
        }
      }
    }
    val r = getLog(ref)
    if (has(input, "retainedVersionId"))
      retained(r, all(ref)("source").str, input("retainedVersionId"), warnings)
    val copies = Arr.from(all.indices.map { i =>
      val report = Obj("source" -> all(i)("source"))
      status.get(i) match {
        case Some(s) =>
          report("status") = Str(s)
          if (s != "unavailable")
            getLog(i).lines.lastOption
              .map(lineId)
              .filter(_ != Null)
              .foreach(id => report("versionId") = id)
        case None =>
          val ls = getLog(i).lines; val behind = ls.size < r.lines.size
          report("status") = Str(if (behind) "behind" else "current");
          report("versionId") = lineId(ls.last)
          if (behind)
            warnings.value += Obj(
              "code" -> "copy-behind",
              "source" -> all(i)("source"),
              "message" -> "copy is behind"
            )
      }
      report
    })
    if (
      copies.arr.count(c =>
        Set("current", "behind")(c("status").str)
      ) < default(options, "minCopies", Num(1)).num
    ) fail("min-copies-not-met")
    result(r, options, warnings, Some(copies))
  }
  def resolve(input: Value): Value = {
    try {
      val now = time(get(input, "now")).getOrElse(fail("invalid-option"))
      val options =
        if (get(input, "options") == Null) Obj() else input("options")
      if (
        !obj(options) || !options.obj.keys.forall(
          Set("versionId", "versionTime", "versionNumber", "minCopies")
        )
      ) fail("invalid-option")
      if (
        Seq("versionId", "versionTime", "versionNumber").count(
          has(options, _)
        ) > 1
      ) fail("invalid-option")
      if (has(options, "versionId") && !string(options("versionId")))
        fail("invalid-option")
      if (has(options, "versionTime") && time(options("versionTime")).isEmpty)
        fail("invalid-option")
      Seq("versionNumber", "minCopies").foreach(k =>
        if (has(options, k) && (!integer(options(k)) || options(k).num < 1))
          fail("invalid-option")
      )
      if (has(input, "copies") || default(options, "minCopies", Num(1)).num > 1)
        return resolveCopies(input, now, options)
      val v = verifyLog(input("log").str, input.obj.get("witness"), now)
      if (v.entries.isEmpty)
        return Obj("valid" -> false, "error" -> v.failure.get.report)
      val warnings = Arr()
      if (has(input, "retainedVersionId"))
        retained(v, "primary", input("retainedVersionId"), warnings)
      result(v, options, warnings)
    } catch {
      case e: ProtocolError => Obj("valid" -> false, "error" -> e.report)
    }
  }
  def dispatch(op: String, input: Value): Value = op match {
    case "jcs"        => Obj("output" -> jcs(parse(input("text").str)))
    case "hash"       => Obj("output" -> hash(input("data").str))
    case "key-hash"   => Obj("output" -> hash(input("multikey").str))
    case "multikey"   => Obj("multikey" -> multikey(input("seed").str))
    case "scid"       => Obj("scid" -> scid(input("entry")))
    case "entry-hash" =>
      Obj("hash" -> entryHash(input("entry"), input("previousVersionId").str))
    case "sign" =>
      Obj("proof" -> sign(input("document"), input("seed").str, input))
    case "verify"  => Obj("valid" -> verify(input("document"), input("proof")))
    case "witness" =>
      Obj(
        "proof" -> sign(
          Obj("versionId" -> input("versionId")),
          input("seed").str,
          input
        )
      )
    case "create"  => create(input)
    case "update"  => update(input)
    case "resolve" => resolve(input)
    case _         => throw IllegalArgumentException("unknown operation " + op)
  }
}
