/// did:vh (docs/didvh-profile.md). A did:vh DID log is verified by the VH-Log
/// code with the did:vh specialisation; this library adds the DID syntax, the
/// srcLog/srcWitness and DID URL rules, the resolution options, and DID
/// Resolution metadata and errors.
library;

import 'dart:convert';
import 'vh_log.dart' as vh;

typedef Json = Map<String, dynamic>;

const didVhMethod = 'did:vh:1.0';
const didPrefix = 'did:vh:';
final _methodSyntax = RegExp(r'^did:vh:(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$');
final _scidSyntax = RegExp(r'^[1-9A-HJ-NP-Za-km-z]{46}$');

/// A did:vh error: invalidDid, invalidDidUrl, invalidOptions, notFound, ...
class DidVhError implements Exception {
  final String code;
  final String message;
  final Json? vhLog;
  DidVhError(this.code, this.message, [this.vhLog]);
  @override
  String toString() => '$code: $message';
}

Never _options(String why) => throw DidVhError('invalidOptions', why);
Never _url(String why) => throw DidVhError('invalidDidUrl', why);

// ---------------------------------------------------------- the DID

/// The SCID of a did:vh DID, or null if it does not match the ABNF.
String? parseDid(dynamic did) {
  if (did is! String || !did.startsWith(didPrefix)) return null;
  final scid = did.substring(didPrefix.length);
  return _scidSyntax.hasMatch(scid) ? scid : null;
}

/// The did:vh specialisation: `method` instead of `logVersion`, a closed
/// parameter set, and `state.id` = `did:vh:<SCID>` in every entry. With
/// [expectedScid], the log must be for that DID.
vh.Spec didVhSpecialisation([String? expectedScid]) => vh.Spec(
      'method',
      [didVhMethod],
      versionSyntax: _methodSyntax,
      extraParameters: const [],
      checkState: (state, scid, n) {
        if ((expectedScid != null && scid != expectedScid) ||
            state['id'] != '$didPrefix$scid') {
          throw vh.ProtocolError('invalid-state', n);
        }
      },
    );

// ---------------------------------------------------------- create / update

/// Creates a did:vh DID log; like VH-Log generation it does not validate its
/// input.
Json createDid(Json input) {
  final r = vh.create({
    'state': input['document'],
    'parameters': input['parameters'],
    'versionTime': input['versionTime'],
    'signers': input['signers'],
  }, 'method', didVhMethod);
  return {
    'log': r['log'],
    'did': '$didPrefix${r['scid']}',
    'scid': r['scid'],
    'versionId': r['versionId'],
  };
}

/// Appends an entry; deactivate with parameters `{deactivated: true}`.
Json updateDid(Json input) => vh.update({
      'log': input['log'],
      'state': input['document'],
      'parameters': input['parameters'],
      'versionTime': input['versionTime'],
      'signers': input['signers'],
    });

// ---------------------------------------------------------- shared URL checks

/// Percent-decodes [s] as UTF-8, or null if an escape or the UTF-8 is
/// malformed.
String? percentDecode(String s) {
  final bytes = <int>[];
  for (var i = 0; i < s.length; i++) {
    if (s[i] == '%') {
      if (i + 3 > s.length ||
          !RegExp(r'^[0-9A-Fa-f]{2}$').hasMatch(s.substring(i + 1, i + 3))) {
        return null;
      }
      bytes.add(int.parse(s.substring(i + 1, i + 3), radix: 16));
      i += 2;
    } else {
      bytes.addAll(utf8.encode(s[i]));
    }
  }
  try {
    return utf8.decode(bytes);
  } on FormatException {
    return null;
  }
}

/// Unicode White_Space (profile §3.2).
bool _whitespace(int c) =>
    (c >= 0x09 && c <= 0x0d) ||
    c == 0x20 ||
    c == 0x85 ||
    c == 0xa0 ||
    c == 0x1680 ||
    (c >= 0x2000 && c <= 0x200a) ||
    c == 0x2028 ||
    c == 0x2029 ||
    c == 0x202f ||
    c == 0x205f ||
    c == 0x3000;

bool _octet(String s) =>
    RegExp(r'^(0|[1-9][0-9]{0,2})$').hasMatch(s) && int.parse(s) <= 255;

bool _loopbackHost(String host) {
  if (host == 'localhost' || host == '[::1]') return true;
  final parts = host.split('.');
  return parts.length == 4 && parts.every(_octet) && parts[0] == '127';
}

bool _domainName(String host) {
  final name = host.endsWith('.') ? host.substring(0, host.length - 1) : host;
  if (name.isEmpty || name.length > 253) return false;
  final labels = name.split('.');
  if (RegExp(r'^[0-9]+$').hasMatch(labels.last)) return false;
  return labels.every(
      (l) => RegExp(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$').hasMatch(l));
}

final _printable = RegExp(r'^[\x21-\x7e]+$');
final _schemeSyntax = RegExp(r'^([A-Za-z][A-Za-z0-9+.-]*):(.*)$', dotAll: true);

/// Splits `scheme:rest` (profile §3.1 steps 1–2), the scheme lowercased.
(String, String)? _splitScheme(dynamic value) {
  if (value is! String || !_printable.hasMatch(value)) return null;
  final m = _schemeSyntax.firstMatch(value);
  return m == null ? null : (m[1]!.toLowerCase(), m[2]!);
}

/// Checks an http(s) authority (profile §3.1 step 4).
bool _authority(String authority, String scheme) {
  if (authority.contains('@')) return false;
  String host;
  String? port;
  if (authority.startsWith('[')) {
    final close = authority.indexOf(']');
    if (close < 0) return false;
    host = authority.substring(0, close + 1);
    final after = authority.substring(close + 1);
    if (after.isNotEmpty) {
      if (!after.startsWith(':')) return false;
      port = after.substring(1);
    }
  } else {
    final colon = authority.indexOf(':');
    host = colon < 0 ? authority : authority.substring(0, colon);
    if (colon >= 0) port = authority.substring(colon + 1);
  }
  host = host.toLowerCase();
  if (port != null &&
      !(RegExp(r'^[0-9]{1,5}$').hasMatch(port) && int.parse(port) <= 65535)) {
    return false;
  }
  if (scheme == 'http') return _loopbackHost(host);
  return !host.startsWith('[') && _domainName(host);
}

/// Checks the segments of a path starting with `/`: each is percent-decoded
/// and must not be `.` or `..` or contain `/`, `\` or NUL. With [strict]
/// (`src`), also non-empty and not starting or ending with White_Space.
bool _segments(String path, bool strict) {
  for (final raw in path.substring(1).split('/')) {
    final s = percentDecode(raw);
    if (s == null ||
        s == '.' ||
        s == '..' ||
        s.contains('/') ||
        s.contains('\\') ||
        s.contains('\u0000')) {
      return false;
    }
    if (strict &&
        (s.isEmpty ||
            _whitespace(s.runes.first) ||
            _whitespace(s.runes.last))) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------- srcLog / srcWitness

/// Validates a srcLog or srcWitness reference (profile §3.1); returns its
/// kind: `web`, `loopback`, `file` or `other`.
String checkRef(dynamic ref) {
  final parts = _splitScheme(ref);
  if (parts == null) _options('not a printable-ASCII absolute URL');
  final (scheme, rest) = parts;
  if (rest.contains('#')) _options('reference must not have a fragment');
  if (scheme == 'https' || scheme == 'http') {
    if (!rest.startsWith('//')) _options('missing authority');
    final tail = rest.substring(2);
    final end = tail.indexOf(RegExp(r'[/?]'));
    final auth = end < 0 ? tail : tail.substring(0, end);
    final after = end < 0 ? '' : tail.substring(end);
    final q = after.indexOf('?');
    final path = q < 0 ? after : after.substring(0, q);
    if (!_authority(auth, scheme)) {
      _options(scheme == 'http'
          ? 'http is only allowed with a loopback host'
          : 'invalid https host');
    }
    if (path.isEmpty) _options('reference must have a path');
    if (!_segments(path, false)) _options('invalid path segment');
    return scheme == 'http' ? 'loopback' : 'web';
  }
  if (scheme == 'file') {
    if (rest.contains('?')) _options('file URL must not have a query');
    String path;
    if (rest.startsWith('//')) {
      final slash = rest.indexOf('/', 2);
      if (slash < 0) _options('file URL needs an absolute path');
      final host = rest.substring(2, slash).toLowerCase();
      if (host != '' && host != 'localhost') {
        _options('file URL host must be empty or localhost');
      }
      path = rest.substring(slash);
    } else {
      if (!rest.startsWith('/')) _options('file URL needs an absolute path');
      path = rest;
    }
    if (!_segments(path, false)) _options('invalid path segment');
    return 'file';
  }
  if (rest.isEmpty) _options('empty URL');
  return 'other';
}

// ---------------------------------------------------------- the src DID URL parameter

/// Validates a (percent-decoded) `src` DID URL parameter and derives the
/// srcLog and srcWitness references from it (profile §3.2).
Json srcReferences(dynamic src) {
  final parts = _splitScheme(src);
  if (parts == null) _url('src is not a printable-ASCII absolute URL');
  final (scheme, rest) = parts;
  if (rest.contains('?') || rest.contains('#')) {
    _url('src must not have a query or fragment');
  }
  if (scheme == 'http' || scheme == 'file') {
    _url('$scheme is not allowed in a DID URL');
  }
  if (!rest.startsWith('//') || rest.length == 2 || rest[2] == '/') {
    _url('src is not a hierarchical URL with an authority');
  }
  final base = rest.endsWith('/') ? rest.substring(0, rest.length - 1) : rest;
  if (scheme == 'https') {
    final slash = base.indexOf('/', 2);
    final auth = slash < 0 ? base.substring(2) : base.substring(2, slash);
    final path = slash < 0 ? '' : base.substring(slash);
    if (!_authority(auth, 'https')) _url('invalid https host');
    if (path.isNotEmpty && !_segments(path, true)) _url('invalid path segment');
  }
  final location = '$scheme:$base';
  return {
    'srcLog': '$location/did.jsonl',
    'srcWitness': '$location/did-witness.json',
  };
}

// ---------------------------------------------------------- DID URLs

const _urlParameters = ['src', 'versionId', 'versionTime', 'versionNumber'];
const _optionOnly = [
  'didLog',
  'didWitness',
  'srcLog',
  'srcWitness',
  'checkWatchers',
  'extraWatchers',
  'minCopies',
  'includeDidLog',
];

/// Parses a did:vh DID URL as a dereferencer does (profile §4):
/// `{did, options, fragment?}`.
Json parseDidUrl(dynamic didUrl) {
  if (didUrl is! String) _url('DID URL is not a string');
  final hash = didUrl.indexOf('#');
  final beforeFragment = hash < 0 ? didUrl : didUrl.substring(0, hash);
  final q = beforeFragment.indexOf('?');
  final did = q < 0 ? beforeFragment : beforeFragment.substring(0, q);
  if (parseDid(did) == null) _url('not a did:vh DID');
  final seen = <String>{};
  final options = <String, dynamic>{};
  if (q >= 0) {
    for (final pair in beforeFragment.substring(q + 1).split('&')) {
      final eq = pair.indexOf('=');
      if (eq < 0) _url('query parameter has no value');
      final key = percentDecode(pair.substring(0, eq));
      final value = percentDecode(pair.substring(eq + 1));
      if (key == null || value == null) _url('malformed percent-encoding');
      if (_optionOnly.contains(key)) _url('$key is a resolution option');
      if (!_urlParameters.contains(key)) continue;
      if (!seen.add(key)) _url('$key given more than once');
      if (key == 'src') {
        options.addAll(srcReferences(value));
      } else if (key == 'versionNumber') {
        if (!RegExp(r'^[1-9][0-9]{0,15}$').hasMatch(value)) {
          _url('versionNumber must be a positive integer');
        }
        options[key] = double.parse(value);
      } else {
        options[key] = value;
      }
    }
  }
  return {
    'did': did,
    'options': options,
    if (hash >= 0) 'fragment': didUrl.substring(hash + 1),
  };
}

// ---------------------------------------------------------- resolve

bool _positiveInteger(dynamic v) => vh.integer(v) && v >= 1;

bool _watcherUrl(dynamic v) =>
    v is String &&
    v.startsWith('https://') &&
    _printable.hasMatch(v) &&
    v.length > 8 &&
    !'/?#'.contains(v[8]);

/// did:vh resolution options validation (profile §5, step 2).
Json _validateOptions(dynamic o, bool remote) {
  if (o is! Map<String, dynamic>)
    _options('resolution options must be an object');
  bool has(String k) => o.containsKey(k);
  if (has('didLog') == has('srcLog')) {
    _options('exactly one of didLog and srcLog must be given');
  }
  if (has('didWitness') && has('srcWitness')) {
    _options('at most one of didWitness and srcWitness may be given');
  }
  if (has('didLog') && o['didLog'] is! String) {
    _options('didLog must be a string');
  }
  if (has('didWitness') && o['didWitness'] is! List) {
    _options('didWitness must be an array');
  }
  for (final key in ['srcLog', 'srcWitness']) {
    if (!has(key)) continue;
    final kind = checkRef(o[key]);
    if (remote && (kind == 'file' || kind == 'loopback')) {
      _options('$key: a resolver that serves other systems must not use '
          'file or loopback references');
    }
  }
  if (['versionId', 'versionTime', 'versionNumber'].where(has).length > 1) {
    _options(
        'at most one of versionId, versionTime and versionNumber may be given');
  }
  if (has('versionId') && o['versionId'] is! String) {
    _options('versionId must be a string');
  }
  if (has('versionTime') && vh.time(o['versionTime']) == null) {
    _options('versionTime must be a whole-second UTC ISO 8601 time');
  }
  if (has('versionNumber') && !_positiveInteger(o['versionNumber'])) {
    _options('versionNumber must be a positive integer');
  }
  if (has('checkWatchers')) {
    final c = o['checkWatchers'];
    if (c != 'all' && !(vh.integer(c) && c >= 0)) {
      _options('checkWatchers must be a non-negative integer or "all"');
    }
  }
  if (has('extraWatchers') &&
      !(o['extraWatchers'] is List &&
          (o['extraWatchers'] as List).every(_watcherUrl))) {
    _options('extraWatchers must be an array of https URLs');
  }
  if (has('minCopies') && !_positiveInteger(o['minCopies'])) {
    _options('minCopies must be a positive integer');
  }
  if (has('includeDidLog') && o['includeDidLog'] is! bool) {
    _options('includeDidLog must be a boolean');
  }
  return o;
}

const _errors = {
  'not-found': 'notFound',
  'invalid-option': 'invalidOptions',
  'fork-detected': 'logForked',
  'min-copies-not-met': 'insufficientCopies',
  'unsupported-log-version': 'featureNotSupported',
};

DidVhError _fromVhLog(Json report) => DidVhError(
    _errors[report['code']] ?? 'invalidDid', report['message'], report);

Json _failure(DidVhError e) => {
      'didResolutionMetadata': {
        'error': e.code,
        'problemDetails': {
          'title': e.code,
          'detail': e.message,
          if (e.vhLog != null) 'vhLog': e.vhLog,
        },
      },
      'didDocument': null,
      'didDocumentMetadata': <String, dynamic>{},
    };

String _currentTime() =>
    '${DateTime.now().toUtc().toIso8601String().substring(0, 19)}Z';

/// did:vh `resolve(did, resolutionOptions)` (profile §5). This resolver is
/// offline: it verifies a log passed in `didLog` (and `didWitness`), and
/// returns `featureNotSupported` where it would have to retrieve anything.
/// [now] is an ISO 8601 time (the current time if null); [remote] says
/// whether the resolver serves other systems.
Json resolveDid(dynamic did,
    [dynamic resolutionOptions = const {}, String? now, bool remote = false]) {
  try {
    final scid = parseDid(did);
    if (scid == null) throw DidVhError('invalidDid', 'not a did:vh DID');
    final o = _validateOptions(resolutionOptions, remote);
    if (o.containsKey('srcLog')) {
      throw DidVhError('featureNotSupported',
          'this resolver does not retrieve srcLog references');
    }
    if ((o['checkWatchers'] ?? 0) != 0 ||
        ((o['extraWatchers'] as List?)?.isNotEmpty ?? false)) {
      throw DidVhError('featureNotSupported',
          'this resolver does not retrieve copies from watchers');
    }
    final spec = didVhSpecialisation(scid);
    final clock = now ?? _currentTime();
    final log = o['didLog'] as String;
    // Whether the log needs witnessing does not depend on the witness file.
    // Without one, the first entry that needs it fails, which cuts it from
    // the entries.
    final unwitnessed = vh.verifyLog(log, vh.absent,
        vh.time(clock) ?? DateTime.now().millisecondsSinceEpoch ~/ 1000, spec);
    final witnessed =
        unwitnessed['failure']?['code'] == 'witness-threshold-not-met' ||
            (unwitnessed['entries'] as List).any((e) => e['rule'] != null);
    if (witnessed && o.containsKey('srcWitness')) {
      throw DidVhError('featureNotSupported',
          'this resolver does not retrieve srcWitness references');
    }
    final result = vh.resolve({
      'log': log,
      'now': clock,
      'options': {
        for (final k in [
          'versionId',
          'versionTime',
          'versionNumber',
          'minCopies'
        ])
          if (o.containsKey(k)) k: o[k],
      },
      if (o.containsKey('didWitness')) 'witness': o['didWitness'],
    }, spec);
    if (result['valid'] != true) throw _fromVhLog(result['error']);
    final selected =
        ['versionId', 'versionTime', 'versionNumber'].any(o.containsKey);
    final error = result['error'];
    if (!selected && error?['code'] == 'unsupported-log-version') {
      throw _fromVhLog(error);
    }
    final m = result['metadata'] as Json;
    // A deactivated DID's document is not returned; earlier versions still
    // are (profile §5).
    final isLast = m['versionTime'] == m['updated'];
    final warnings = m['warnings'] as List;
    Json? didLog;
    if (o['includeDidLog'] == true) {
      final ls = vh.lines(log);
      final first = result['firstInvalidVersion'];
      final valid = first == null ? ls.length : (first as num).toInt() - 1;
      didLog = {
        'didLog': ls.take(valid).map((l) => '$l\n').join(),
        if (witnessed)
          'didWitness': o['didWitness'] is List ? o['didWitness'] : [],
      };
    }
    return {
      'didResolutionMetadata': {
        'contentType': 'application/did+json',
        if (warnings.isNotEmpty) 'warnings': warnings,
        ...?didLog,
      },
      'didDocument':
          m['deactivated'] == true && isLast ? null : result['state'],
      'didDocumentMetadata': {
        'versionId': m['versionId'],
        'versionTime': m['versionTime'],
        'created': m['created'],
        'updated': m['updated'],
        'scid': m['scid'],
        'deactivated': m['deactivated'],
        'ttl': m['ttl'],
        if (m['witness'] != null) 'witness': m['witness'],
        'watchers': m['watchers'],
      },
    };
  } on DidVhError catch (e) {
    return _failure(e);
  }
}

// ---------------------------------------------------------- driver operations

/// Runs [fn], turning a did:vh error into `{valid: false, error}`.
Json _rejected(Json Function() fn) {
  try {
    return {'valid': true, ...fn()};
  } on DidVhError catch (e) {
    return {'valid': false, 'error': e.code};
  }
}

/// The did:vh driver operations (docs/interop-protocol.md, "did:vh
/// operations").
Json dispatch(String op, Json input) => switch (op) {
      'didvh-create' => createDid(input),
      'didvh-update' => updateDid(input),
      'didvh-resolve' => resolveDid(
          input['did'],
          input.containsKey('options') ? input['options'] : <String, dynamic>{},
          input['now'] is String ? input['now'] : null,
          input['remote'] == true),
      'didvh-ref' => _rejected(() => {'kind': checkRef(input['ref'])}),
      'didvh-src' => _rejected(() => srcReferences(input['src'])),
      'didvh-did-url' => _rejected(() => parseDidUrl(input['didUrl'])),
      _ => throw ArgumentError('unknown operation $op'),
    };
