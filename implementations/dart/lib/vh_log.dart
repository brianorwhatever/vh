import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

typedef Json = Map<String, dynamic>;
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
final absent = Object();

class ProtocolError implements Exception {
  final Json report;
  ProtocolError(String code, [int? version, Json? fork])
      : report = {
          'code': code,
          'version': version,
          'message': code,
          if (fork != null) 'fork': fork,
        };
}

Never fail(String code, [int? version, Json? fork]) =>
    throw ProtocolError(code, version, fork);
dynamic normalize(dynamic v) {
  if (v is Map)
    return <String, dynamic>{
      for (final k in v.keys) normalize(k) as String: normalize(v[k])
    };
  if (v is List) return v.map(normalize).toList();
  if (v is num) {
    final d = v.toDouble();
    if (!d.isFinite) throw FormatException('non-finite number');
    return d;
  }
  if (v is String) {
    for (var i = 0; i < v.length; i++) {
      final c = v.codeUnitAt(i);
      if (c >= 0xd800 && c <= 0xdbff) {
        if (++i >= v.length ||
            v.codeUnitAt(i) < 0xdc00 ||
            v.codeUnitAt(i) > 0xdfff) throw FormatException('lone surrogate');
      } else if (c >= 0xdc00 && c <= 0xdfff) {
        throw FormatException('lone surrogate');
      }
    }
  }
  return v;
}

dynamic parse(String text) => normalize(jsonDecode(text));
String number(num v) {
  final d = v.toDouble();
  if (!d.isFinite) throw FormatException('non-finite number');
  if (d == 0) return '0';
  final parts = d.abs().toString().toLowerCase().split('e');
  final mantissa = parts[0].split('.');
  var digits = mantissa.join().replaceFirst(RegExp(r'0+$'), '');
  var point =
      mantissa[0].length + (parts.length == 2 ? int.parse(parts[1]) : 0);
  while (digits.startsWith('0')) {
    digits = digits.substring(1);
    point--;
  }
  String body;
  if (point > 0 && point <= 21) {
    body = digits.length <= point
        ? digits.padRight(point, '0')
        : '${digits.substring(0, point)}.${digits.substring(point)}';
  } else if (point <= 0 && point > -6) {
    body = '0.${'0' * -point}$digits';
  } else {
    final power = point - 1;
    body =
        '${digits[0]}${digits.length > 1 ? '.${digits.substring(1)}' : ''}e${power >= 0 ? '+' : ''}$power';
  }
  return '${d < 0 ? '-' : ''}$body';
}

String jcs(dynamic v) {
  if (v is Map) {
    final keys = v.keys.cast<String>().toList()..sort();
    return '{${keys.map((k) => '${jsonEncode(k)}:${jcs(v[k])}').join(',')}}';
  }
  if (v is List) return '[${v.map(jcs).join(',')}]';
  if (v is num) return number(v);
  return jsonEncode(v);
}

String encode(List<int> bytes) {
  var n = BigInt.zero;
  for (final b in bytes) {
    n = (n << 8) + BigInt.from(b);
  }
  var out = '';
  while (n > BigInt.zero) {
    out = alphabet[(n % BigInt.from(58)).toInt()] + out;
    n ~/= BigInt.from(58);
  }
  return '1' * bytes.takeWhile((b) => b == 0).length + out;
}

List<int>? decode(dynamic s) {
  if (s is! String) return null;
  var n = BigInt.zero;
  for (final c in s.split('')) {
    final d = alphabet.indexOf(c);
    if (d < 0) return null;
    n = n * BigInt.from(58) + BigInt.from(d);
  }
  final out = <int>[];
  while (n > BigInt.zero) {
    out.add((n & BigInt.from(255)).toInt());
    n >>= 8;
  }
  return [
    ...List.filled(s.split('').takeWhile((c) => c == '1').length, 0),
    ...out.reversed
  ];
}

List<int> sha(String s) => crypto.sha256.convert(utf8.encode(s)).bytes;
String hash(String s) => encode([0x12, 0x20, ...sha(s)]);
String checkHash(dynamic s) {
  final b = decode(s);
  return b == null
      ? 'not-base58'
      : b.length == 34 && b[0] == 0x12 && b[1] == 0x20
          ? 'ok'
          : 'unsupported-algorithm';
}

List<int>? publicKey(dynamic mk) {
  if (mk is! String || !mk.startsWith('z')) return null;
  final b = decode(mk.substring(1));
  return b != null && b.length == 34 && b[0] == 0xed && b[1] == 1
      ? b.sublist(2)
      : null;
}

ed.PrivateKey signer(String hex) {
  if (!RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(hex))
    throw FormatException('seed must be 32-byte hex');
  return ed.newKeyFromSeed(Uint8List.fromList([
    for (var i = 0; i < 64; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16)
  ]));
}

String multikey(String seed) =>
    'z${encode([0xed, 1, ...ed.public(signer(seed)).bytes])}';
String? methodKey(dynamic vm) {
  if (vm is! String || !vm.startsWith('did:key:')) return null;
  final parts = vm.substring(8).split('#');
  return parts.length == 2 &&
          parts[0] == parts[1] &&
          publicKey(parts[0]) != null
      ? parts[0]
      : null;
}

Uint8List signingInput(dynamic document, dynamic config) => Uint8List.fromList([
      ...sha(jcs(config)),
      ...sha(jcs(document)),
    ]);
Json sign(dynamic document, String seed, [Json options = const {}]) {
  final mk = multikey(seed);
  final config = <String, dynamic>{
    'type': 'DataIntegrityProof',
    'cryptosuite': 'eddsa-jcs-2022',
    'verificationMethod': options.containsKey('verificationMethod')
        ? options['verificationMethod']
        : 'did:key:$mk#$mk',
    if (options.containsKey('created')) 'created': options['created'],
    'proofPurpose': 'assertionMethod'
  };
  return {
    ...config,
    'proofValue':
        'z${encode(ed.sign(signer(seed), signingInput(document, config)))}'
  };
}

// Profile §2; ed25519_edwards checks the curve and equation.
bool _admissiblePoint(List<int> encoded) {
  var n = BigInt.zero;
  for (var i = 31; i >= 0; i--) {
    n = (n << 8) | BigInt.from(encoded[i] & (i == 31 ? 127 : 255));
  }
  return n <
          BigInt.parse(
              '57896044618658097711785492504343953926634992332820282019728792003956564819949') &&
      !{
        BigInt.parse('0'),
        BigInt.parse('1'),
        BigInt.parse(
            '2707385501144840649318225287225658788936804267575313519463743609750303402022'),
        BigInt.parse(
            '55188659117513257062467267217118295137698188065244968500265048394206261417927'),
        BigInt.parse(
            '57896044618658097711785492504343953926634992332820282019728792003956564819948')
      }.contains(n);
}

bool verify(dynamic document, dynamic proof) {
  try {
    if (proof is! Map ||
        proof['type'] != 'DataIntegrityProof' ||
        proof['cryptosuite'] != 'eddsa-jcs-2022' ||
        proof['proofPurpose'] != 'assertionMethod') return false;
    final mk = methodKey(proof['verificationMethod']);
    final value = proof['proofValue'];
    if (mk == null || value is! String || !value.startsWith('z')) return false;
    final sig = decode(value.substring(1));
    if (sig == null || sig.length != 64) return false;
    if (!_admissiblePoint(publicKey(mk)!) ||
        !_admissiblePoint(sig.sublist(0, 32))) return false;
    final config = Map<String, dynamic>.from(proof)..remove('proofValue');
    return ed.verify(ed.PublicKey(Uint8List.fromList(publicKey(mk)!)),
        signingInput(document, config), Uint8List.fromList(sig));
  } catch (_) {
    return false;
  }
}

Json withoutProof(Json e) => Map<String, dynamic>.from(e)..remove('proof');
String scid(Json e) => hash(jcs(withoutProof(e)));
String entryHash(Json e, String previous) =>
    hash(jcs({...withoutProof(e), 'versionId': previous}));
List<String> lines(String log) {
  final a = log.split('\n');
  if (a.last == '') a.removeLast();
  return a;
}

Json create(Json input) {
  final p = {
    'logVersion': 'vh-log:1.0',
    'scid': '{SCID}',
    ...input['parameters'] as Map
  };
  var e = <String, dynamic>{
    'versionId': '{SCID}',
    'versionTime': input['versionTime'],
    'parameters': p,
    'state': input['state']
  };
  final id = scid(e);
  e = parse(jcs(e).replaceAll('{SCID}', id));
  e['versionId'] = '1-${entryHash(e, id)}';
  e['proof'] = [
    for (final s in input['signers'])
      sign(e, s, {'created': input['versionTime']})
  ];
  return {'log': '${jcs(e)}\n', 'scid': id, 'versionId': e['versionId']};
}

Json update(Json input) {
  final previous = parse(lines(input['log']).last)['versionId'] as String;
  final e = <String, dynamic>{
    'versionId': previous,
    'versionTime': input['versionTime'],
    'parameters': input['parameters'] ?? <String, dynamic>{},
    'state': input['state']
  };
  e['versionId'] =
      '${int.parse(previous.split('-')[0]) + 1}-${entryHash(e, previous)}';
  e['proof'] = [
    for (final s in input['signers'])
      sign(e, s, {'created': input['versionTime']})
  ];
  return {
    'log':
        '${input['log']}${input['log'].endsWith('\n') ? '' : '\n'}${jcs(e)}\n',
    'versionId': e['versionId']
  };
}

int? time(dynamic value) {
  if (value is! String) return null;
  final m = RegExp(
          r'^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\+00:00)$')
      .firstMatch(value);
  if (m == null) return null;
  final a = [for (var i = 1; i <= 6; i++) int.parse(m[i]!)];
  final d = DateTime.utc(a[0], a[1], a[2], a[3], a[4], a[5]);
  if (d.year != a[0] ||
      d.month != a[1] ||
      d.day != a[2] ||
      d.hour != a[3] ||
      d.minute != a[4] ||
      d.second != a[5]) return null;
  return d.millisecondsSinceEpoch ~/ 1000;
}

bool integer(dynamic v) => v is num && v.isFinite && v == v.truncateToDouble();
bool strings(dynamic v) => v is List && v.every((x) => x is String);
Json parameters(Json raw, Json? previous, int n) {
  if (raw.values.any((v) => v == null)) fail('invalid-parameter', n);
  if ((previous == null && !raw.containsKey('logVersion')) ||
      (raw.containsKey('logVersion') && raw['logVersion'] != 'vh-log:1.0'))
    fail('unsupported-log-version', n);
  if (previous != null
      ? raw.containsKey('scid')
      : (raw['scid'] is! String || !raw.containsKey('updateKeys')))
    fail('invalid-parameter', n);
  if (raw.containsKey('updateKeys') &&
      (!strings(raw['updateKeys']) ||
          !(raw['updateKeys'] as List).every((k) => publicKey(k) != null)))
    fail('invalid-parameter', n);
  if (raw.containsKey('nextKeyHashes') &&
      (!strings(raw['nextKeyHashes']) ||
          !(raw['nextKeyHashes'] as List).every((h) => checkHash(h) == 'ok')))
    fail('invalid-parameter', n);
  final p = <String, dynamic>{...?previous};
  if (previous == null)
    p.addAll(
        {'nextKeyHashes': [], 'witness': null, 'watchers': [], 'ttl': 3600});
  for (final k in [
    'logVersion',
    'scid',
    'updateKeys',
    'nextKeyHashes',
    'witness',
    'watchers',
    'ttl'
  ]) {
    if (raw.containsKey(k)) p[k] = raw[k];
  }
  p['deactivated'] = raw['deactivated'] ?? false;
  if (raw.containsKey('witness')) {
    final w = raw['witness'];
    if (w is! Map) fail('invalid-parameter', n);
    if (w.isEmpty) {
      p['witness'] = null;
    } else {
      final ws = w['witnesses'];
      if (ws is! List ||
          ws.isEmpty ||
          !ws.every((x) =>
              x is Map &&
              x['id'] is String &&
              x['id'].startsWith('did:key:') &&
              publicKey(x['id'].substring(8)) != null))
        fail('invalid-parameter', n);
      // Valid witness identifiers are ASCII did:key multikeys, already NFC.
      final ids = ws.map((x) => x['id']).toSet();
      if (ids.length != ws.length ||
          !integer(w['threshold']) ||
          w['threshold'] < 1 ||
          w['threshold'] > ids.length) fail('invalid-parameter', n);
      p['witness'] = {'threshold': w['threshold'], 'witnesses': ws};
    }
  }
  if (raw.containsKey('watchers') &&
      (!strings(raw['watchers']) ||
          !(raw['watchers'] as List).every((u) =>
              RegExp(r'^[\x21-\x7e]+$').hasMatch(u) &&
              RegExp(r'^https?://[^/?#]').hasMatch(u))))
    fail('invalid-parameter', n);
  if (p['deactivated'] is! bool ||
      !integer(p['ttl']) ||
      p['ttl'] < 0 ||
      p['ttl'] > 2147483648) fail('invalid-parameter', n);
  if (previous != null && (previous['nextKeyHashes'] as List).isNotEmpty) {
    if (!raw.containsKey('updateKeys') || !raw.containsKey('nextKeyHashes'))
      fail('prerotation-violation', n);
    for (final key in raw['updateKeys']) {
      if (!previous['nextKeyHashes'].contains(hash(key)))
        fail('prerotation-violation', n);
    }
  }
  return p;
}

Json verifyEntry(Json e, Json? previous, int now) {
  final n = previous == null ? 1 : previous['n'] + 1 as int;
  if (previous != null && previous['p']['deactivated'] == true)
    fail('entry-after-deactivation', n);
  if (e.length != 5 ||
      !['parameters', 'proof', 'state', 'versionId', 'versionTime']
          .every(e.containsKey) ||
      e['versionId'] is! String ||
      e['versionTime'] is! String ||
      e['parameters'] is! Map<String, dynamic> ||
      e['state'] is! Map ||
      e['proof'] is! List) fail('invalid-entry', n);
  final p = parameters(e['parameters'], previous?['p'], n);
  final keys =
      previous == null || (previous['p']['nextKeyHashes'] as List).isNotEmpty
          ? p['updateKeys']
          : previous['p']['updateKeys'];
  final rule = previous == null ||
          (e['parameters'].containsKey('witness') &&
              previous['p']['witness'] == null)
      ? p['witness']
      : previous['p']['witness'];
  if ((e['proof'] as List).isEmpty) fail('invalid-proof', n);
  for (final proof in e['proof']) {
    final mk = proof is Map ? methodKey(proof['verificationMethod']) : null;
    if (mk == null) fail('invalid-proof', n);
    if (!keys.contains(mk)) fail('unauthorized-key', n);
    if (!verify(withoutProof(e), proof)) fail('invalid-proof', n);
  }
  final m = RegExp(r'^([1-9][0-9]*)-([^-]+)$').firstMatch(e['versionId']);
  if (m == null || int.tryParse(m[1]!) != n) fail('invalid-version-id', n);
  final status = checkHash(m[2]);
  if (status == 'not-base58') fail('invalid-version-id', n);
  if (status != 'ok') fail('invalid-hash-algorithm', n);
  if (entryHash(e, previous == null ? p['scid'] : previous['e']['versionId']) !=
      m[2]) fail('entry-hash-mismatch', n);
  final t = time(e['versionTime']);
  if (t == null || (previous != null && t <= previous['time']))
    fail('invalid-version-time', n);
  if (t > now + 300) fail('future-version-time', n);
  if (previous == null) {
    final status = checkHash(p['scid']);
    if (status == 'unsupported-algorithm') fail('invalid-hash-algorithm', n);
    if (status != 'ok') fail('scid-mismatch', n);
    final restored = parse(jcs({...withoutProof(e), 'versionId': '{SCID}'})
        .replaceAll(p['scid'], '{SCID}'));
    if (scid(restored) != p['scid']) fail('scid-mismatch', n);
  }
  return {'e': e, 'p': p, 'n': n, 'time': t, 'rule': rule};
}

Json verifyLog(String log, dynamic witness, int now) {
  final ls = lines(log);
  var entries = <Json>[];
  Json? failure;
  if (ls.isEmpty)
    return {
      'entries': entries,
      'lines': ls,
      'failure': ProtocolError('invalid-log').report
    };
  for (var i = 0; i < ls.length; i++) {
    try {
      dynamic e;
      try {
        e = parse(ls[i]);
      } catch (_) {
        fail('invalid-log', i + 1);
      }
      if (e is! Map<String, dynamic>) fail('invalid-log', i + 1);
      entries.add(verifyEntry(e, entries.isEmpty ? null : entries.last, now));
    } on ProtocolError catch (e) {
      failure = e.report;
      break;
    }
  }
  for (var i = 0; i < entries.length; i++) {
    final rule = entries[i]['rule'];
    if (rule == null) continue;
    final file = identical(witness, absent) ? [] : witness;
    String? code;
    if (file is! List ||
        !file.every((r) =>
            r is Map && r['versionId'] is String && r['proof'] is List)) {
      code = 'invalid-witness-file';
    } else {
      final allowed = (rule['witnesses'] as List).map((w) => w['id']).toSet();
      final ids = <String>{};
      for (final r in file) {
        final index =
            entries.indexWhere((x) => x['e']['versionId'] == r['versionId']);
        if (index < i) continue;
        for (final proof in r['proof']) {
          final mk =
              proof is Map ? methodKey(proof['verificationMethod']) : null;
          final id = 'did:key:$mk';
          if (mk != null &&
              allowed.contains(id) &&
              verify({'versionId': r['versionId']}, proof)) ids.add(id);
        }
      }
      if (ids.length < rule['threshold']) code = 'witness-threshold-not-met';
    }
    if (code != null) {
      failure = ProtocolError(code, i + 1).report;
      entries = entries.take(i).toList();
      break;
    }
  }
  return {'entries': entries, 'lines': ls, 'failure': failure};
}

dynamic lineValue(dynamic line) {
  try {
    return parse(line);
  } catch (_) {
    return null;
  }
}

String? lineId(dynamic line) {
  final v = lineValue(line);
  return v is Map && v['versionId'] is String ? v['versionId'] : null;
}

void retained(Json v, String source, dynamic id, List<Json> warnings) {
  final m = id is String ? RegExp(r'^([1-9][0-9]*)-').firstMatch(id) : null;
  if (m == null) fail('invalid-option');
  final n = int.tryParse(m[1]!);
  if (n == null) fail('invalid-option');
  final entries = v['entries'] as List;
  if (entries.length < n) {
    warnings.add({
      'code': 'retained-version-not-found',
      'message': 'retained version not found'
    });
  } else if (entries[n - 1]['e']['versionId'] != id) {
    fail('fork-detected', n, {
      'version': n,
      'copies': [
        {'source': 'retained', 'versionId': id},
        {'source': source, 'versionId': entries[n - 1]['e']['versionId']}
      ]
    });
  }
}

Json result(Json v, Json options, List<Json> warnings, [List<Json>? copies]) {
  final entries = v['entries'] as List, ls = v['lines'] as List;
  final failure = v['failure'];
  dynamic target;
  if (options.containsKey('versionId')) {
    for (final x in entries) {
      if (x['e']['versionId'] == options['versionId']) target = x;
    }
    if (target == null &&
        ls.skip(entries.length).any((l) => lineId(l) == options['versionId']))
      fail(failure['code'], failure['version']);
  } else if (options.containsKey('versionNumber')) {
    final n = (options['versionNumber'] as num).toInt();
    if (n <= entries.length) target = entries[n - 1];
    if (target == null && n <= ls.length)
      fail(failure['code'], failure['version']);
  } else if (options.containsKey('versionTime')) {
    final t = time(options['versionTime'])!;
    if (failure != null) {
      final e = lineValue(ls[entries.length]);
      final invalidTime = e is Map ? time(e['versionTime']) : null;
      if (invalidTime != null && invalidTime <= t)
        fail(failure['code'], failure['version']);
    }
    for (final x in entries) {
      if (x['time'] <= t) target = x;
    }
  } else {
    target = entries.last;
  }
  if (target == null) fail('not-found');
  final first = entries.first, last = entries.last;
  if (failure != null)
    warnings.add({'code': 'invalid-entries', 'message': failure['message']});
  final meta = <String, dynamic>{
    'versionId': target['e']['versionId'],
    'versionTime': target['e']['versionTime'],
    'versionNumber': target['n'],
    'created': first['e']['versionTime'],
    'updated': last['e']['versionTime'],
    'scid': first['p']['scid'],
    'deactivated': last['p']['deactivated'],
    'ttl': last['p']['ttl'],
    'witness': last['p']['witness'],
    'watchers': last['p']['watchers'],
    'updateKeys': target['p']['updateKeys'],
    'nextKeyHashes': target['p']['nextKeyHashes'],
    'warnings': warnings,
    if (copies != null) 'copies': copies
  };
  return {
    'valid': true,
    'state': target['e']['state'],
    'metadata': meta,
    'firstInvalidVersion': failure == null ? null : entries.length + 1,
    'error': failure
  };
}

Json resolveCopies(Json input, int now, Json options) {
  final all = <dynamic>[
    {
      'source': 'primary',
      'log': input['log'],
      'witness': input.containsKey('witness') ? input['witness'] : absent
    },
    ...?input['copies']
  ];
  final warnings = <Json>[], status = <int, String>{}, cache = <int, Json>{};
  Json get(int i) => cache.putIfAbsent(
      i,
      () => verifyLog(all[i]['log'],
          all[i].containsKey('witness') ? all[i]['witness'] : absent, now));
  void invalid(int i) {
    status[i] = 'invalid';
    warnings.add({
      'code': 'copy-invalid',
      'source': all[i]['source'],
      'message': 'copy fails verification'
    });
  }

  for (var i = 0; i < all.length; i++) {
    if (all[i].containsKey('unavailable')) {
      status[i] = 'unavailable';
      warnings.add({
        'code': 'copy-unavailable',
        'source': all[i]['source'],
        'message': all[i]['unavailable']
      });
    }
  }
  int? ref;
  for (var i = 0; i < all.length; i++) {
    if (status.containsKey(i)) continue;
    if (get(i)['failure'] == null) {
      ref = i;
      break;
    }
    invalid(i);
  }
  if (ref == null) return {'valid': false, 'error': get(0)['failure']};
  final matched = {ref};
  for (var i = 0; i < all.length; i++) {
    if (status.containsKey(i) || matched.contains(i)) continue;
    final r = get(ref!),
        c = get(i),
        rl = r['lines'] as List,
        cl = c['lines'] as List;
    if (cl.isEmpty) {
      invalid(i);
      continue;
    }
    final same = cl.length <= rl.length &&
        lineId(cl.last) == r['entries'][cl.length - 1]['e']['versionId'];
    final extendsLog = cl.length > rl.length &&
        lineId(cl[rl.length - 1]) ==
            (r['entries'] as List).last['e']['versionId'];
    if (same) {
      matched.add(i);
    } else if (extendsLog && c['failure'] == null) {
      matched.add(i);
      ref = i;
    } else if (c['failure'] != null) {
      invalid(i);
    } else {
      var k = 0;
      while (k < rl.length && k < cl.length && lineId(rl[k]) == lineId(cl[k])) {
        k++;
      }
      fail('fork-detected', k + 1, {
        'version': k + 1,
        'copies': [
          {
            'source': all[ref]['source'],
            'versionId': k < rl.length ? lineId(rl[k]) : ''
          },
          {
            'source': all[i]['source'],
            'versionId': k < cl.length ? lineId(cl[k]) : ''
          }
        ]
      });
    }
  }
  final r = get(ref!);
  if (input.containsKey('retainedVersionId'))
    retained(r, all[ref]['source'], input['retainedVersionId'], warnings);
  final copies = <Json>[];
  for (var i = 0; i < all.length; i++) {
    final report = <String, dynamic>{'source': all[i]['source']};
    if (status.containsKey(i)) {
      report['status'] = status[i];
      if (status[i] != 'unavailable') {
        final ls = get(i)['lines'] as List;
        final id = ls.isEmpty ? null : lineId(ls.last);
        if (id != null) report['versionId'] = id;
      }
    } else {
      final ls = get(i)['lines'] as List;
      final behind = ls.length < (r['lines'] as List).length;
      report.addAll({
        'status': behind ? 'behind' : 'current',
        'versionId': lineId(ls.last)
      });
      if (behind)
        warnings.add({
          'code': 'copy-behind',
          'source': all[i]['source'],
          'message': 'copy is behind'
        });
    }
    copies.add(report);
  }
  if (copies.where((c) => ['current', 'behind'].contains(c['status'])).length <
      (options['minCopies'] ?? 1)) fail('min-copies-not-met');
  return result(r, options, warnings, copies);
}

Json resolve(Json input) {
  try {
    final now = time(input['now']);
    if (now == null) fail('invalid-option');
    final options = input['options'] ?? <String, dynamic>{};
    if (options is! Map<String, dynamic> ||
        options.keys.any((k) => ![
              'versionId',
              'versionTime',
              'versionNumber',
              'minCopies'
            ].contains(k))) fail('invalid-option');
    if (['versionId', 'versionTime', 'versionNumber']
            .where(options.containsKey)
            .length >
        1) fail('invalid-option');
    if (options.containsKey('versionId') && options['versionId'] is! String)
      fail('invalid-option');
    if (options.containsKey('versionTime') &&
        time(options['versionTime']) == null) fail('invalid-option');
    for (final k in ['versionNumber', 'minCopies']) {
      if (options.containsKey(k) && (!integer(options[k]) || options[k] < 1))
        fail('invalid-option');
    }
    if (input.containsKey('copies') || (options['minCopies'] ?? 1) > 1)
      return resolveCopies(input, now, options);
    final v = verifyLog(input['log'],
        input.containsKey('witness') ? input['witness'] : absent, now);
    if ((v['entries'] as List).isEmpty)
      return {'valid': false, 'error': v['failure']};
    final warnings = <Json>[];
    if (input.containsKey('retainedVersionId'))
      retained(v, 'primary', input['retainedVersionId'], warnings);
    return result(v, options, warnings);
  } on ProtocolError catch (e) {
    return {'valid': false, 'error': e.report};
  }
}

Json dispatch(String op, Json input) => switch (op) {
      'jcs' => {'output': jcs(parse(input['text']))},
      'hash' => {'output': hash(input['data'])},
      'key-hash' => {'output': hash(input['multikey'])},
      'multikey' => {'multikey': multikey(input['seed'])},
      'scid' => {'scid': scid(input['entry'])},
      'entry-hash' => {
          'hash': entryHash(input['entry'], input['previousVersionId'])
        },
      'sign' => {'proof': sign(input['document'], input['seed'], input)},
      'verify' => {'valid': verify(input['document'], input['proof'])},
      'witness' => {
          'proof': sign({'versionId': input['versionId']}, input['seed'], input)
        },
      'create' => create(input),
      'update' => update(input),
      'resolve' => resolve(input),
      _ => throw ArgumentError('unknown operation $op'),
    };
