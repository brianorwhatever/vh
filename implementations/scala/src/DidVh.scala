package vhlog

import ujson.*
import java.nio.ByteBuffer
import java.nio.charset.{CharacterCodingException, CodingErrorAction}
import java.nio.charset.StandardCharsets.UTF_8

/**
 * did:vh (docs/didvh-profile.md). A did:vh DID log is verified by the VH-Log code with the
 * did:vh specialisation; this object adds the DID syntax, the srcLog/srcWitness and DID URL
 * rules, the resolution options, and DID Resolution metadata and errors.
 */
object DidVh {
  val Method = "did:vh:1.0"
  val Prefix = "did:vh:"
  private val methodSyntax = "did:vh:(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)".r
  private val scidSyntax = "[1-9A-HJ-NP-Za-km-z]{46}".r

  /** A did:vh error: invalidDid, invalidDidUrl, invalidOptions, notFound, ... */
  final case class DidVhError(code: String, detail: String, vhLog: Value = Null)
      extends RuntimeException(detail)

  private def invalid(code: String)(why: String): Nothing = throw DidVhError(code, why)
  private val options = invalid("invalidOptions")
  private val url = invalid("invalidDidUrl")

  // ---------------------------------------------------------- the DID

  /** The SCID of a did:vh DID, or None if it does not match the ABNF. */
  def parseDid(did: Value): Option[String] = did.strOpt
    .filter(_.startsWith(Prefix))
    .map(_.drop(Prefix.length))
    .filter(scidSyntax.matches)

  /**
   * The did:vh specialisation: method instead of logVersion, a closed parameter set, and
   * state.id = did:vh:SCID in every entry. With expectedScid, the log must be for that DID.
   */
  def specialisation(expectedScid: Option[String] = None): VHLog.Spec = VHLog.Spec(
    "method",
    Seq(Method),
    Some(methodSyntax),
    Some(Seq.empty),
    Some((state, scid, n) =>
      if (expectedScid.exists(_ != scid) || state.objOpt.flatMap(_.get("id")) != Some(Str(Prefix + scid)))
        throw VHLog.ProtocolError("invalid-state", Num(n))
    )
  )

  // ---------------------------------------------------------- create / update

  /** Creates a did:vh DID log; like VH-Log generation it does not validate its input. */
  def create(input: Value): Value = {
    val r = VHLog.create(
      Obj(
        "state" -> input("document"),
        "parameters" -> input("parameters"),
        "versionTime" -> input("versionTime"),
        "signers" -> input("signers")
      ),
      "method",
      Method
    )
    Obj("log" -> r("log"), "did" -> (Prefix + r("scid").str), "scid" -> r("scid"), "versionId" -> r("versionId"))
  }

  /** Appends an entry; deactivate with parameters {deactivated: true}. */
  def update(input: Value): Value = {
    val u = Obj(
      "log" -> input("log"),
      "state" -> input("document"),
      "versionTime" -> input("versionTime"),
      "signers" -> input("signers")
    )
    input.obj.get("parameters").filter(_ != Null).foreach(p => u("parameters") = p)
    VHLog.update(u)
  }

  // ---------------------------------------------------------- shared URL checks

  /** Percent-decodes s as UTF-8, or None if an escape or the UTF-8 is malformed. */
  def percentDecode(s: String): Option[String] = {
    val out = ByteBuffer.allocate(s.length * 4)
    var i = 0
    while (i < s.length) {
      if (s.charAt(i) == '%') {
        val hex = s.slice(i + 1, i + 3)
        if (!hex.matches("[0-9A-Fa-f]{2}")) return None
        out.put(Integer.parseInt(hex, 16).toByte); i += 3
      } else {
        val cp = s.codePointAt(i)
        out.put(new String(Character.toChars(cp)).getBytes(UTF_8)); i += Character.charCount(cp)
      }
    }
    out.flip()
    try
      Some(
        UTF_8.newDecoder
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(out)
          .toString
      )
    catch { case _: CharacterCodingException => None }
  }

  /** Unicode White_Space (profile §3.2). */
  private def whitespace(c: Int): Boolean =
    (c >= 0x09 && c <= 0x0d) || c == 0x20 || c == 0x85 || c == 0xa0 || c == 0x1680 ||
      (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f ||
      c == 0x205f || c == 0x3000

  private def octet(s: String) = s.matches("0|[1-9][0-9]{0,2}") && s.toInt <= 255

  private def loopbackHost(host: String): Boolean = host == "localhost" || host == "[::1]" || {
    val parts = host.split("\\.", -1)
    parts.length == 4 && parts.forall(octet) && parts(0) == "127"
  }

  private def domainName(host: String): Boolean = {
    val name = host.stripSuffix(".")
    if (name.isEmpty || name.length > 253) false
    else {
      val labels = name.split("\\.", -1)
      !labels.last.matches("[0-9]+") && labels.forall(_.matches("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"))
    }
  }

  private val schemeSyntax = "(?s)([A-Za-z][A-Za-z0-9+.-]*):(.*)".r

  /** Splits scheme:rest (profile §3.1 steps 1–2), the scheme lowercased. */
  private def splitScheme(value: Value): Option[(String, String)] = value.strOpt
    .filter(_.matches("[\\x21-\\x7e]+"))
    .collect { case schemeSyntax(scheme, rest) => (scheme.toLowerCase(java.util.Locale.ROOT), rest) }

  /** Checks an http(s) authority (profile §3.1 step 4). */
  private def authority(authority: String, scheme: String): Boolean = {
    if (authority.contains("@")) return false
    var host = ""
    var port: Option[String] = None
    if (authority.startsWith("[")) {
      val close = authority.indexOf(']')
      if (close < 0) return false
      host = authority.take(close + 1)
      val after = authority.drop(close + 1)
      if (after.nonEmpty) {
        if (!after.startsWith(":")) return false
        port = Some(after.drop(1))
      }
    } else {
      val colon = authority.indexOf(':')
      host = if (colon < 0) authority else authority.take(colon)
      if (colon >= 0) port = Some(authority.drop(colon + 1))
    }
    host = host.toLowerCase(java.util.Locale.ROOT)
    if (port.exists(p => !(p.matches("[0-9]{1,5}") && p.toInt <= 65535))) false
    else if (scheme == "http") loopbackHost(host)
    else !host.startsWith("[") && domainName(host)
  }

  /**
   * Checks the segments of a path starting with "/": each is percent-decoded and must not be
   * "." or ".." or contain "/", "\" or NUL. With strict (src), also non-empty and not starting
   * or ending with White_Space.
   */
  private def segments(path: String, strict: Boolean): Boolean =
    path.drop(1).split("/", -1).forall { raw =>
      percentDecode(raw).exists { s =>
        s != "." && s != ".." && !s.exists(c => c == '/' || c == '\\' || c == '\u0000') &&
        (!strict || (s.nonEmpty && !whitespace(s.codePointAt(0)) && !whitespace(s.codePointBefore(s.length))))
      }
    }

  // ---------------------------------------------------------- srcLog / srcWitness

  /** Validates a srcLog or srcWitness reference (profile §3.1); returns its kind. */
  def checkRef(ref: Value): String = {
    val (scheme, rest) = splitScheme(ref).getOrElse(options("not a printable-ASCII absolute URL"))
    if (rest.contains("#")) options("reference must not have a fragment")
    if (scheme == "https" || scheme == "http") {
      if (!rest.startsWith("//")) options("missing authority")
      val tail = rest.drop(2)
      val end = tail.indexWhere(c => c == '/' || c == '?')
      val auth = if (end < 0) tail else tail.take(end)
      val after = if (end < 0) "" else tail.drop(end)
      val path = after.takeWhile(_ != '?')
      if (!authority(auth, scheme))
        options(if (scheme == "http") "http is only allowed with a loopback host" else "invalid https host")
      if (path.isEmpty) options("reference must have a path")
      if (!segments(path, false)) options("invalid path segment")
      if (scheme == "http") "loopback" else "web"
    } else if (scheme == "file") {
      if (rest.contains("?")) options("file URL must not have a query")
      val path =
        if (rest.startsWith("//")) {
          val slash = rest.indexOf('/', 2)
          if (slash < 0) options("file URL needs an absolute path")
          val host = rest.slice(2, slash).toLowerCase(java.util.Locale.ROOT)
          if (host.nonEmpty && host != "localhost") options("file URL host must be empty or localhost")
          rest.drop(slash)
        } else if (rest.startsWith("/")) rest
        else options("file URL needs an absolute path")
      if (!segments(path, false)) options("invalid path segment")
      "file"
    } else {
      if (rest.isEmpty) options("empty URL")
      "other"
    }
  }

  // ---------------------------------------------------------- the src DID URL parameter

  /** Validates a decoded src value and derives srcLog and srcWitness (profile §3.2). */
  def srcReferences(src: Value): Obj = {
    val (scheme, rest) = splitScheme(src).getOrElse(url("src is not a printable-ASCII absolute URL"))
    if (rest.contains("?") || rest.contains("#")) url("src must not have a query or fragment")
    if (scheme == "http" || scheme == "file") url(s"$scheme is not allowed in a DID URL")
    if (!rest.startsWith("//") || rest.length == 2 || rest.charAt(2) == '/')
      url("src is not a hierarchical URL with an authority")
    val base = rest.stripSuffix("/")
    if (scheme == "https") {
      val slash = base.indexOf('/', 2)
      val auth = if (slash < 0) base.drop(2) else base.slice(2, slash)
      val path = if (slash < 0) "" else base.drop(slash)
      if (!authority(auth, "https")) url("invalid https host")
      if (path.nonEmpty && !segments(path, true)) url("invalid path segment")
    }
    val location = s"$scheme:$base"
    Obj("srcLog" -> s"$location/did.jsonl", "srcWitness" -> s"$location/did-witness.json")
  }

  // ---------------------------------------------------------- DID URLs

  private val urlParameters = Set("src", "versionId", "versionTime", "versionNumber")
  private val optionOnly = Set(
    "didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog"
  )

  /** Parses a did:vh DID URL as a dereferencer does (profile §4): {did, options, fragment?}. */
  def parseDidUrl(didUrl: Value): Obj = {
    val s = didUrl.strOpt.getOrElse(url("DID URL is not a string"))
    val hash = s.indexOf('#')
    val beforeFragment = if (hash < 0) s else s.take(hash)
    val q = beforeFragment.indexOf('?')
    val did = if (q < 0) beforeFragment else beforeFragment.take(q)
    if (parseDid(Str(did)).isEmpty) url("not a did:vh DID")
    val seen = scala.collection.mutable.Set.empty[String]
    val opts = Obj()
    if (q >= 0) beforeFragment.drop(q + 1).split("&", -1).foreach { pair =>
      val eq = pair.indexOf('=')
      if (eq < 0) url("query parameter has no value")
      val (key, value) = (percentDecode(pair.take(eq)), percentDecode(pair.drop(eq + 1))) match {
        case (Some(k), Some(v)) => (k, v)
        case _                  => url("malformed percent-encoding")
      }
      if (optionOnly(key)) url(s"$key is a resolution option")
      if (urlParameters(key)) {
        if (!seen.add(key)) url(s"$key given more than once")
        key match {
          case "src" => srcReferences(Str(value)).obj.foreach { case (k, v) => opts(k) = v }
          case "versionNumber" =>
            if (!value.matches("[1-9][0-9]{0,15}")) url("versionNumber must be a positive integer")
            opts(key) = Num(value.toDouble)
          case _ => opts(key) = Str(value)
        }
      }
    }
    val out = Obj("did" -> did, "options" -> opts)
    if (hash >= 0) out("fragment") = Str(s.drop(hash + 1))
    out
  }

  // ---------------------------------------------------------- resolve

  private def positiveInteger(v: Value) = VHLog.integer(v) && v.num >= 1

  private def watcherUrl(v: Value) = v.strOpt.exists(s =>
    s.startsWith("https://") && s.matches("[\\x21-\\x7e]+") && s.length > 8 && !"/?#".contains(s.charAt(8))
  )

  /** did:vh resolution options validation (profile §5, step 2). */
  private def validateOptions(o: Value, remote: Boolean): Obj = {
    val m = o match {
      case m: Obj => m
      case _      => options("resolution options must be an object")
    }
    def has(k: String) = m.value.contains(k)
    if (has("didLog") == has("srcLog")) options("exactly one of didLog and srcLog must be given")
    if (has("didWitness") && has("srcWitness")) options("at most one of didWitness and srcWitness may be given")
    if (has("didLog") && m("didLog").strOpt.isEmpty) options("didLog must be a string")
    if (has("didWitness") && m("didWitness").arrOpt.isEmpty) options("didWitness must be an array")
    for (key <- Seq("srcLog", "srcWitness") if has(key)) {
      val kind = checkRef(m(key))
      if (remote && (kind == "file" || kind == "loopback"))
        options(s"$key: a resolver that serves other systems must not use file or loopback references")
    }
    if (Seq("versionId", "versionTime", "versionNumber").count(has) > 1)
      options("at most one of versionId, versionTime and versionNumber may be given")
    if (has("versionId") && m("versionId").strOpt.isEmpty) options("versionId must be a string")
    if (has("versionTime") && VHLog.time(m("versionTime")).isEmpty)
      options("versionTime must be a whole-second UTC ISO 8601 time")
    if (has("versionNumber") && !positiveInteger(m("versionNumber")))
      options("versionNumber must be a positive integer")
    if (has("checkWatchers") && m("checkWatchers") != Str("all") &&
        !(VHLog.integer(m("checkWatchers")) && m("checkWatchers").num >= 0))
      options("checkWatchers must be a non-negative integer or \"all\"")
    if (has("extraWatchers") && !m("extraWatchers").arrOpt.exists(_.forall(watcherUrl)))
      options("extraWatchers must be an array of https URLs")
    if (has("minCopies") && !positiveInteger(m("minCopies"))) options("minCopies must be a positive integer")
    if (has("includeDidLog") && m("includeDidLog").boolOpt.isEmpty) options("includeDidLog must be a boolean")
    m
  }

  private val errors = Map(
    "not-found" -> "notFound",
    "invalid-option" -> "invalidOptions",
    "fork-detected" -> "logForked",
    "min-copies-not-met" -> "insufficientCopies",
    "unsupported-log-version" -> "featureNotSupported"
  )

  private def fromVhLog(report: Value): DidVhError =
    DidVhError(errors.getOrElse(report("code").str, "invalidDid"), report("message").str, report)

  private def failure(e: DidVhError): Value = {
    val details = Obj("title" -> e.code, "detail" -> e.detail)
    if (e.vhLog != Null) details("vhLog") = e.vhLog
    Obj(
      "didResolutionMetadata" -> Obj("error" -> e.code, "problemDetails" -> details),
      "didDocument" -> Null,
      "didDocumentMetadata" -> Obj()
    )
  }

  private def currentTime = java.time.Instant.now.toString.replaceAll("\\.\\d+Z$", "Z")

  /**
   * did:vh resolve(did, resolutionOptions) (profile §5). This resolver is offline: it verifies
   * a log passed in didLog (and didWitness), and gives featureNotSupported where it would
   * have to retrieve anything. now is an ISO 8601 time (None for the current time); remote
   * says whether the resolver serves other systems.
   */
  def resolve(did: Value, resolutionOptions: Value = Obj(), now: Option[String] = None, remote: Boolean = false): Value =
    try {
      val scid = parseDid(did).getOrElse(throw DidVhError("invalidDid", "not a did:vh DID"))
      val o = validateOptions(resolutionOptions, remote)
      def has(k: String) = o.value.contains(k)
      if (has("srcLog")) throw DidVhError("featureNotSupported", "this resolver does not retrieve srcLog references")
      if (o.value.get("checkWatchers").exists(_ != Num(0)) || o.value.get("extraWatchers").exists(_.arr.nonEmpty))
        throw DidVhError("featureNotSupported", "this resolver does not retrieve copies from watchers")
      val spec = specialisation(Some(scid))
      val clock = now.getOrElse(currentTime)
      val log = o("didLog").str
      // Whether the log needs witnessing does not depend on the witness file. Without
      // one, the first entry that needs it fails, which cuts it from the entries.
      val unwitnessed = VHLog.verifyLog(
        log, None, VHLog.time(Str(clock)).getOrElse(java.time.Instant.now.getEpochSecond), spec
      )
      val witnessed = unwitnessed.failure.exists(_.code == "witness-threshold-not-met") ||
        unwitnessed.entries.exists(_.rule != Null)
      if (witnessed && has("srcWitness"))
        throw DidVhError("featureNotSupported", "this resolver does not retrieve srcWitness references")
      val vhOptions = Obj()
      for (k <- Seq("versionId", "versionTime", "versionNumber", "minCopies") if has(k)) vhOptions(k) = o(k)
      val in = Obj("log" -> log, "now" -> clock, "options" -> vhOptions)
      if (has("didWitness")) in("witness") = o("didWitness")
      val result = VHLog.resolve(in, spec)
      if (result("valid") != Bool(true)) throw fromVhLog(result("error"))
      val selected = Seq("versionId", "versionTime", "versionNumber").exists(has)
      if (!selected && result("error") != Null && result("error")("code") == Str("unsupported-log-version"))
        throw fromVhLog(result("error"))
      val m = result("metadata")
      val docMeta = Obj(
        "versionId" -> m("versionId"),
        "versionTime" -> m("versionTime"),
        "created" -> m("created"),
        "updated" -> m("updated"),
        "scid" -> m("scid"),
        "deactivated" -> m("deactivated"),
        "ttl" -> m("ttl")
      )
      if (m("witness") != Null) docMeta("witness") = m("witness")
      docMeta("watchers") = m("watchers")
      val meta = Obj("contentType" -> "application/did+json")
      if (m("warnings").arr.nonEmpty) meta("warnings") = m("warnings")
      if (o.value.get("includeDidLog").contains(Bool(true))) {
        val lines = VHLog.lines(log)
        val valid = if (result("firstInvalidVersion") == Null) lines.size else result("firstInvalidVersion").num.toInt - 1
        meta("didLog") = Str(lines.take(valid).map(_ + "\n").mkString)
        if (witnessed) meta("didWitness") = o.value.get("didWitness").filter(_.arrOpt.isDefined).getOrElse(Arr())
      }
      Obj(
        "didResolutionMetadata" -> meta,
        "didDocument" -> (if (m("deactivated") == Bool(true) && !selected) Null else result("state")),
        "didDocumentMetadata" -> docMeta
      )
    } catch { case e: DidVhError => failure(e) }

  // ---------------------------------------------------------- driver operations

  /** Runs fn, turning a did:vh error into {valid: false, error}. */
  private def rejected(fn: => Obj): Value =
    try {
      val out = Obj("valid" -> true); fn.obj.foreach { case (k, v) => out(k) = v }; out
    } catch { case e: DidVhError => Obj("valid" -> false, "error" -> e.code) }

  /** The did:vh driver operations (docs/interop-protocol.md, "did:vh operations"). */
  def dispatch(op: String, input: Value): Value = op match {
    case "didvh-create" => create(input)
    case "didvh-update" => update(input)
    case "didvh-resolve" =>
      resolve(
        input.obj.getOrElse("did", Null),
        input.obj.getOrElse("options", Obj()),
        input.obj.get("now").flatMap(_.strOpt),
        input.obj.get("remote").contains(Bool(true))
      )
    case "didvh-ref"     => rejected(Obj("kind" -> checkRef(input.obj.getOrElse("ref", Null))))
    case "didvh-src"     => rejected(srcReferences(input.obj.getOrElse("src", Null)))
    case "didvh-did-url" => rejected(parseDidUrl(input.obj.getOrElse("didUrl", Null)))
    case _               => throw IllegalArgumentException("unknown operation " + op)
  }
}
