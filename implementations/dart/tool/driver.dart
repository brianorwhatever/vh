import 'dart:convert';
import 'dart:io';
import 'package:vh_log/vh_log.dart';

void respond(String line) {
  dynamic id;
  try {
    final request = parse(line);
    id = request['id'];
    stdout.writeln(jcs({
      'id': id,
      'ok': true,
      'result': dispatch(request['op'], request['input']),
    }));
  } catch (e) {
    stdout.writeln(jsonEncode({'id': id, 'ok': false, 'error': e.toString()}));
  }
}

Future<void> main() async {
  var pending = '';
  await for (final chunk in stdin.transform(utf8.decoder)) {
    pending += chunk;
    int end;
    while ((end = pending.indexOf('\n')) >= 0) {
      respond(pending.substring(0, end));
      pending = pending.substring(end + 1);
    }
  }
  if (pending.isNotEmpty) respond(pending);
}
