# VH-Log interop profile 0. All protocol operations are implemented in Ruby.
require 'json'
require 'openssl'
require 'date'

module VHLog
  extend self
  ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.freeze
  ABSENT = Object.new.freeze
  class Error < StandardError
    attr_reader :report
    def initialize(code, version = nil, fork = nil)
      super(code)
      @report = {'code'=>code, 'version'=>version, 'message'=>code}
      @report['fork'] = fork if fork
    end
  end
  def fail!(code, version = nil, fork = nil)
    raise Error.new(code, version, fork)
  end
  def parse(text)
    normalize(JSON.parse(text))
  end
  def normalize(v)
    case v
    when Hash
      raise ArgumentError, 'invalid Unicode key' unless v.keys.all?(&:valid_encoding?)
      v.transform_values { |x| normalize(x) }
    when Array then v.map { |x| normalize(x) }
    when String
      raise ArgumentError, 'invalid Unicode string' unless v.valid_encoding?
      v
    when Numeric
      f = v.to_f
      raise ArgumentError, 'non-finite JSON number' unless f.finite?
      f
    else v
    end
  end
  # Ruby's shortest round-trip digits, formatted using ECMAScript's thresholds.
  def number(v)
    f = v.to_f
    raise ArgumentError, 'non-finite number' unless f.finite?
    return '0' if f.zero?
    sign = f.negative? ? '-' : ''
    mantissa, exponent = f.abs.to_s.downcase.split('e')
    whole, fraction = mantissa.split('.')
    digits = (whole + (fraction || '')).sub(/0+\z/, '')
    point = whole.length + (exponent || '0').to_i
    while digits.start_with?('0')
      digits = digits[1..]
      point -= 1
    end
    result = if point > 0 && point <= 21
      digits.length <= point ? digits.ljust(point, '0') : digits[0...point] + '.' + digits[point..]
    elsif point <= 0 && point > -6
      '0.' + '0' * -point + digits
    else
      power = point - 1
      digits[0] + (digits.length > 1 ? '.' + digits[1..] : '') + 'e' + (power >= 0 ? '+' : '') + power.to_s
    end
    sign + result
  end
  def jcs(v)
    case v
    when Hash
      '{' + v.keys.sort_by { |k| k.encode('UTF-16BE').bytes }.map { |k| JSON.generate(k) + ':' + jcs(v[k]) }.join(',') + '}'
    when Array then '[' + v.map { |x| jcs(x) }.join(',') + ']'
    when Numeric then number(v)
    else JSON.generate(v)
    end
  end
  def encode(bytes)
    n = bytes.unpack1('H*').to_i(16)
    s = ''
    while n > 0
      n, r = n.divmod(58)
      s.prepend(ALPHABET[r])
    end
    '1' * bytes.bytes.take_while(&:zero?).length + s
  end
  def decode(s)
    return nil unless s.is_a?(String)
    n = 0
    s.each_char do |c|
      d = ALPHABET.index(c)
      return nil unless d
      n = n * 58 + d
    end
    hex = n.to_s(16)
    hex = '0' + hex if hex.length.odd?
    "\0".b * s[/\A1*/].length + (n.zero? ? ''.b : [hex].pack('H*'))
  end
  def sha(s)
    OpenSSL::Digest::SHA256.digest(s)
  end
  def hash_b58(s)
    encode("\x12\x20".b + sha(s))
  end
  def check_hash(s)
    b = decode(s)
    return 'not-base58' unless b
    b.bytesize == 34 && b.start_with?("\x12\x20".b) ? 'ok' : 'unsupported-algorithm'
  end
  def public_key(mk)
    return nil unless mk.is_a?(String) && mk.start_with?('z')
    b = decode(mk[1..])
    b && b.bytesize == 34 && b.start_with?("\xed\x01".b) ? b.byteslice(2,32) : nil
  end
  def signer(seed)
    raise ArgumentError, 'seed must be 32 bytes of hex' unless seed.is_a?(String) && /\A[0-9a-fA-F]{64}\z/.match?(seed)
    OpenSSL::PKey.read(['302e020100300506032b657004220420' + seed].pack('H*'))
  end
  def multikey(seed)
    'z' + encode("\xed\x01".b + signer(seed).public_to_der.byteslice(-32,32))
  end
  def method_key(vm)
    return nil unless vm.is_a?(String)
    m = /\Adid:key:([^#]+)#(.+)\z/.match(vm)
    m && m[1] == m[2] && public_key(m[1]) ? m[1] : nil
  end
  def signing_input(document, config)
    sha(jcs(config)) + sha(jcs(document))
  end
  def sign(document, seed, options = {})
    mk = multikey(seed)
    config = {'type'=>'DataIntegrityProof', 'cryptosuite'=>'eddsa-jcs-2022',
              'verificationMethod'=>options.fetch('verificationMethod', "did:key:#{mk}##{mk}")}
    config['created'] = options['created'] if options.key?('created')
    config['proofPurpose'] = 'assertionMethod'
    config.merge('proofValue'=>'z' + encode(signer(seed).sign(nil, signing_input(document, config))))
  end
  # Profile §2; OpenSSL checks the curve and uncofactored equation.
  def admissible_point(encoded)
    y = encoded.reverse.unpack1('H*').to_i(16) & ((1 << 255) - 1)
    y < 57896044618658097711785492504343953926634992332820282019728792003956564819949 && ![0, 1, 2707385501144840649318225287225658788936804267575313519463743609750303402022, 55188659117513257062467267217118295137698188065244968500265048394206261417927, 57896044618658097711785492504343953926634992332820282019728792003956564819948].include?(y)
  end
  def verify(document, proof)
    return false unless proof.is_a?(Hash) && proof['type'] == 'DataIntegrityProof' && proof['cryptosuite'] == 'eddsa-jcs-2022' && proof['proofPurpose'] == 'assertionMethod'
    mk = method_key(proof['verificationMethod'])
    value = proof['proofValue']
    return false unless mk && value.is_a?(String) && value.start_with?('z')
    signature = decode(value[1..])
    return false unless signature && signature.bytesize == 64
    return false unless admissible_point(public_key(mk)) && admissible_point(signature[0,32])
    key = OpenSSL::PKey.read(['302a300506032b6570032100'].pack('H*') + public_key(mk))
    key.verify(nil, signature, signing_input(document, proof.reject { |k,_| k == 'proofValue' }))
  rescue OpenSSL::PKey::PKeyError, ArgumentError
    false
  end
  def without_proof(e)
    e.reject { |k,_| k == 'proof' }
  end
  def scid(e)
    hash_b58(jcs(without_proof(e)))
  end
  def entry_hash(e, previous)
    hash_b58(jcs(without_proof(e).merge('versionId'=>previous)))
  end
  def lines(log)
    log.split("\n", -1).tap { |a| a.pop if a.last == '' }
  end
  def create(input)
    p = {'logVersion'=>'vh-log:1.0', 'scid'=>'{SCID}'}.merge(input['parameters'])
    e = {'versionId'=>'{SCID}', 'versionTime'=>input['versionTime'], 'parameters'=>p, 'state'=>input['state']}
    id = scid(e)
    e = parse(JSON.generate(e).gsub('{SCID}',id))
    e['versionId'] = '1-' + entry_hash(e,id)
    e['proof'] = input['signers'].map { |s| sign(e,s,{'created'=>input['versionTime']}) }
    {'log'=>JSON.generate(e)+"\n", 'scid'=>id, 'versionId'=>e['versionId']}
  end
  def update(input)
    previous = parse(lines(input['log']).last)['versionId']
    e = {'versionId'=>previous, 'versionTime'=>input['versionTime'], 'parameters'=>input.fetch('parameters',{}), 'state'=>input['state']}
    e['versionId'] = (previous.split('-')[0].to_i + 1).to_s + '-' + entry_hash(e,previous)
    e['proof'] = input['signers'].map { |s| sign(e,s,{'created'=>input['versionTime']}) }
    prefix = input['log'] + (input['log'].end_with?("\n") ? '' : "\n")
    {'log'=>prefix+JSON.generate(e)+"\n", 'versionId'=>e['versionId']}
  end
  def time(value)
    return nil unless value.is_a?(String)
    m = /\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\+00:00)\z/.match(value)
    return nil unless m
    y,mo,d,h,mi,s = m.captures.map(&:to_i)
    return nil unless Date.valid_date?(y,mo,d,Date::GREGORIAN) && h < 24 && mi < 60 && s < 60
    Date.new(y,mo,d,Date::GREGORIAN).jd * 86400 + h * 3600 + mi * 60 + s
  end
  def integer?(v)
    v.is_a?(Numeric) && v.finite? && v == v.to_i
  end
  def strings?(v)
    v.is_a?(Array) && v.all? { |x| x.is_a?(String) }
  end
  def parameters(raw, previous, n)
    fail!('invalid-parameter',n) if raw.values.any?(&:nil?)
    fail!('unsupported-log-version',n) if (!previous && !raw.key?('logVersion')) || (raw.key?('logVersion') && raw['logVersion'] != 'vh-log:1.0')
    fail!('invalid-parameter',n) if previous ? raw.key?('scid') : (!raw['scid'].is_a?(String) || !raw.key?('updateKeys'))
    if raw.key?('updateKeys')
      fail!('invalid-parameter',n) unless strings?(raw['updateKeys']) && raw['updateKeys'].all? { |k| public_key(k) }
    end
    if raw.key?('nextKeyHashes')
      fail!('invalid-parameter',n) unless strings?(raw['nextKeyHashes']) && raw['nextKeyHashes'].all? { |h| check_hash(h) == 'ok' }
    end
    p = (previous || {'nextKeyHashes'=>[], 'witness'=>nil, 'watchers'=>[], 'ttl'=>3600}).merge(raw.select { |k,_| %w[logVersion scid updateKeys nextKeyHashes witness watchers ttl].include?(k) })
    p['deactivated'] = raw.fetch('deactivated',false)
    if raw.key?('witness')
      w = raw['witness']
      fail!('invalid-parameter',n) unless w.is_a?(Hash)
      if w.empty?
        p['witness'] = nil
      else
        ws = w['witnesses']
        fail!('invalid-parameter',n) unless ws.is_a?(Array) && !ws.empty? && ws.all? { |x| x.is_a?(Hash) && x['id'].is_a?(String) && x['id'].start_with?('did:key:') && public_key(x['id'][8..]) }
        ids = ws.map { |x| x['id'].unicode_normalize(:nfc) }
        fail!('invalid-parameter',n) unless ids.uniq.length == ids.length && integer?(w['threshold']) && w['threshold'] >= 1 && w['threshold'] <= ids.length
        p['witness'] = {'threshold'=>w['threshold'], 'witnesses'=>ws}
      end
    end
    if raw.key?('watchers')
      fail!('invalid-parameter',n) unless strings?(raw['watchers']) && raw['watchers'].all? { |u| /\A[\x21-\x7e]+\z/.match?(u) && /\Ahttps?:\/\/[^\/?#]/.match?(u) }
    end
    fail!('invalid-parameter',n) unless [true,false].include?(p['deactivated'])
    fail!('invalid-parameter',n) unless integer?(p['ttl']) && p['ttl'] >= 0 && p['ttl'] <= 2**31
    if previous && !previous['nextKeyHashes'].empty?
      fail!('prerotation-violation',n) unless raw.key?('updateKeys') && raw.key?('nextKeyHashes')
      raw['updateKeys'].each { |key| fail!('prerotation-violation',n) unless previous['nextKeyHashes'].include?(hash_b58(key)) }
    end
    p
  end
  def verify_entry(e, previous, now)
    n = previous ? previous[:n]+1 : 1
    fail!('entry-after-deactivation',n) if previous && previous[:p]['deactivated']
    fail!('invalid-entry',n) unless e.keys.sort == %w[parameters proof state versionId versionTime] && e['versionId'].is_a?(String) && e['versionTime'].is_a?(String) && e['parameters'].is_a?(Hash) && e['state'].is_a?(Hash) && e['proof'].is_a?(Array)
    p = parameters(e['parameters'], previous && previous[:p],n)
    keys = !previous || !previous[:p]['nextKeyHashes'].empty? ? p['updateKeys'] : previous[:p]['updateKeys']
    rule = !previous || (e['parameters'].key?('witness') && !previous[:p]['witness']) ? p['witness'] : previous[:p]['witness']
    fail!('invalid-proof',n) if e['proof'].empty?
    e['proof'].each do |proof|
      mk = proof.is_a?(Hash) && method_key(proof['verificationMethod'])
      fail!('invalid-proof',n) unless mk
      fail!('unauthorized-key',n) unless keys.include?(mk)
      fail!('invalid-proof',n) unless verify(without_proof(e),proof)
    end
    m = /\A([1-9][0-9]*)-([^-]+)\z/.match(e['versionId'])
    fail!('invalid-version-id',n) unless m && m[1].to_i == n
    status = check_hash(m[2])
    fail!('invalid-version-id',n) if status == 'not-base58'
    fail!('invalid-hash-algorithm',n) unless status == 'ok'
    fail!('entry-hash-mismatch',n) unless entry_hash(e, previous ? previous[:e]['versionId'] : p['scid']) == m[2]
    t = time(e['versionTime'])
    fail!('invalid-version-time',n) unless t && (!previous || t > previous[:time])
    fail!('future-version-time',n) if t > now + 300
    unless previous
      status = check_hash(p['scid'])
      fail!('invalid-hash-algorithm',n) if status == 'unsupported-algorithm'
      fail!('scid-mismatch',n) unless status == 'ok'
      restored = parse(JSON.generate(without_proof(e).merge('versionId'=>'{SCID}')).gsub(p['scid'],'{SCID}'))
      fail!('scid-mismatch',n) unless scid(restored) == p['scid']
    end
    {e:e, p:p, n:n, time:t, rule:rule}
  end
  def verify_log(log, witness, now)
    ls = lines(log)
    entries = []
    failure = nil
    return {entries:[], lines:ls, failure:Error.new('invalid-log').report} if ls.empty?
    ls.each_with_index do |line,i|
      begin
        begin
          e = parse(line)
        rescue JSON::ParserError, ArgumentError
          fail!('invalid-log',i+1)
        end
        fail!('invalid-log',i+1) unless e.is_a?(Hash)
        entries << verify_entry(e,entries.last,now)
      rescue Error => error
        failure = error.report
        break
      end
    end
    entries.each_with_index do |e,i|
      next unless e[:rule]
      file = witness.equal?(ABSENT) ? [] : witness
      code = nil
      if !file.is_a?(Array) || !file.all? { |r| r.is_a?(Hash) && r['versionId'].is_a?(String) && r['proof'].is_a?(Array) }
        code = 'invalid-witness-file'
      else
        allowed = e[:rule]['witnesses'].map { |w| w['id'] }
        ids = []
        file.each do |r|
          index = entries.index { |x| x[:e]['versionId'] == r['versionId'] }
          next unless index && index >= i
          r['proof'].each do |proof|
            mk = proof.is_a?(Hash) && method_key(proof['verificationMethod'])
            id = "did:key:#{mk}"
            ids << id if mk && allowed.include?(id) && verify({'versionId'=>r['versionId']},proof)
          end
        end
        code = 'witness-threshold-not-met' if ids.uniq.length < e[:rule]['threshold']
      end
      if code
        failure = Error.new(code,i+1).report
        entries = entries.take(i)
        break
      end
    end
    {entries:entries, lines:ls, failure:failure}
  end
  def line_value(line)
    parse(line)
  rescue JSON::ParserError, ArgumentError, TypeError
    nil
  end
  def line_id(line)
    v = line_value(line)
    v.is_a?(Hash) && v['versionId'].is_a?(String) ? v['versionId'] : nil
  end
  def retained(v, source, id, warnings)
    m = id.is_a?(String) && /\A([1-9][0-9]*)-/.match(id)
    fail!('invalid-option') unless m
    n = m[1].to_i
    if v[:entries].length < n
      warnings << {'code'=>'retained-version-not-found', 'message'=>'retained version not found'}
    elsif v[:entries][n-1][:e]['versionId'] != id
      fail!('fork-detected',n,{'version'=>n,'copies'=>[{'source'=>'retained','versionId'=>id},{'source'=>source,'versionId'=>v[:entries][n-1][:e]['versionId']}]})
    end
  end
  def result(v, options, warnings, copies = nil)
    entries, ls, failure = v.values_at(:entries,:lines,:failure)
    target = nil
    if options.key?('versionId')
      target = entries.find { |x| x[:e]['versionId'] == options['versionId'] }
      if !target && ls.drop(entries.length).any? { |l| line_id(l) == options['versionId'] }
        fail!(failure['code'],failure['version'])
      end
    elsif options.key?('versionNumber')
      n = options['versionNumber'].to_i
      target = entries[n-1]
      fail!(failure['code'],failure['version']) if !target && n <= ls.length
    elsif options.key?('versionTime')
      t = time(options['versionTime'])
      if failure
        e = line_value(ls[entries.length])
        invalid_time = e.is_a?(Hash) && time(e['versionTime'])
        fail!(failure['code'],failure['version']) if invalid_time && invalid_time <= t
      end
      target = entries.reverse.find { |x| x[:time] <= t }
    else
      target = entries.last
    end
    fail!('not-found') unless target
    first, last = entries.first, entries.last
    warnings << {'code'=>'invalid-entries','message'=>failure['message']} if failure
    meta = {'versionId'=>target[:e]['versionId'],'versionTime'=>target[:e]['versionTime'],'versionNumber'=>target[:n],
            'created'=>first[:e]['versionTime'],'updated'=>last[:e]['versionTime'],'scid'=>first[:p]['scid'],
            'deactivated'=>last[:p]['deactivated'],'ttl'=>last[:p]['ttl'],'witness'=>last[:p]['witness'],
            'watchers'=>last[:p]['watchers'],'updateKeys'=>target[:p]['updateKeys'],'nextKeyHashes'=>target[:p]['nextKeyHashes'],'warnings'=>warnings}
    meta['copies'] = copies if copies
    {'valid'=>true,'state'=>target[:e]['state'],'metadata'=>meta,'firstInvalidVersion'=>failure ? entries.length+1 : nil,'error'=>failure}
  end
  def resolve_copies(input, now, options)
    all = [{'source'=>'primary','log'=>input['log'],'witness'=>input.fetch('witness',ABSENT)}] + input.fetch('copies',[])
    warnings, status, cache = [], {}, {}
    get = ->(i) { cache[i] ||= verify_log(all[i]['log'],all[i].fetch('witness',ABSENT),now) }
    invalid = lambda do |i|
      status[i] = 'invalid'
      warnings << {'code'=>'copy-invalid','source'=>all[i]['source'],'message'=>'copy fails verification'}
    end
    all.each_with_index do |c,i|
      if c.key?('unavailable')
        status[i] = 'unavailable'
        warnings << {'code'=>'copy-unavailable','source'=>c['source'],'message'=>c['unavailable']}
      end
    end
    ref = nil
    all.each_index do |i|
      next if status.key?(i)
      if get.call(i)[:failure].nil?
        ref = i
        break
      end
      invalid.call(i)
    end
    return {'valid'=>false,'error'=>get.call(0)[:failure]} unless ref
    matched = [ref]
    all.each_index do |i|
      next if status.key?(i) || matched.include?(i)
      r, c = get.call(ref), get.call(i)
      rl, cl = r[:lines], c[:lines]
      if cl.empty?
        invalid.call(i)
        next
      end
      same = cl.length <= rl.length && line_id(cl.last) == r[:entries][cl.length-1][:e]['versionId']
      extends = cl.length > rl.length && line_id(cl[rl.length-1]) == r[:entries].last[:e]['versionId']
      if same
        matched << i
      elsif extends && c[:failure].nil?
        matched << i
        ref = i
      elsif c[:failure]
        invalid.call(i)
      else
        k = (0...[rl.length,cl.length].min).find { |j| line_id(rl[j]) != line_id(cl[j]) } || [rl.length,cl.length].min
        fail!('fork-detected',k+1,{'version'=>k+1,'copies'=>[{'source'=>all[ref]['source'],'versionId'=>line_id(rl[k]) || ''},{'source'=>all[i]['source'],'versionId'=>line_id(cl[k]) || ''}]})
      end
    end
    r = get.call(ref)
    retained(r,all[ref]['source'],input['retainedVersionId'],warnings) if input.key?('retainedVersionId')
    copies = all.each_with_index.map do |c,i|
      report = {'source'=>c['source']}
      if status.key?(i)
        report['status'] = status[i]
        id = line_id(get.call(i)[:lines].last) unless status[i] == 'unavailable'
        report['versionId'] = id if id
      else
        ls = get.call(i)[:lines]
        behind = ls.length < r[:lines].length
        report.merge!('status'=>behind ? 'behind' : 'current','versionId'=>line_id(ls.last))
        warnings << {'code'=>'copy-behind','source'=>c['source'],'message'=>'copy is behind'} if behind
      end
      report
    end
    fail!('min-copies-not-met') if copies.count { |c| %w[current behind].include?(c['status']) } < options.fetch('minCopies',1)
    result(r,options,warnings,copies)
  end
  def resolve(input)
    now = time(input['now'])
    fail!('invalid-option') unless now
    options = input['options'] || {}
    fail!('invalid-option') unless options.is_a?(Hash) && (options.keys - %w[versionId versionTime versionNumber minCopies]).empty?
    fail!('invalid-option') if (options.keys & %w[versionId versionTime versionNumber]).length > 1
    fail!('invalid-option') if options.key?('versionId') && !options['versionId'].is_a?(String)
    fail!('invalid-option') if options.key?('versionTime') && !time(options['versionTime'])
    %w[versionNumber minCopies].each { |k| fail!('invalid-option') if options.key?(k) && (!integer?(options[k]) || options[k] < 1) }
    return resolve_copies(input,now,options) if input.key?('copies') || options.fetch('minCopies',1) > 1
    v = verify_log(input['log'],input.fetch('witness',ABSENT),now)
    return {'valid'=>false,'error'=>v[:failure]} if v[:entries].empty?
    warnings = []
    retained(v,'primary',input['retainedVersionId'],warnings) if input.key?('retainedVersionId')
    result(v,options,warnings)
  rescue Error => e
    {'valid'=>false,'error'=>e.report}
  end
  def dispatch(op, input)
    case op
    when 'jcs' then {'output'=>jcs(parse(input['text']))}
    when 'hash' then {'output'=>hash_b58(input['data'])}
    when 'key-hash' then {'output'=>hash_b58(input['multikey'])}
    when 'multikey' then {'multikey'=>multikey(input['seed'])}
    when 'scid' then {'scid'=>scid(input['entry'])}
    when 'entry-hash' then {'hash'=>entry_hash(input['entry'],input['previousVersionId'])}
    when 'sign' then {'proof'=>sign(input['document'],input['seed'],input)}
    when 'verify' then {'valid'=>verify(input['document'],input['proof'])}
    when 'witness' then {'proof'=>sign({'versionId'=>input['versionId']},input['seed'],input)}
    when 'create' then create(input)
    when 'update' then update(input)
    when 'resolve' then resolve(input)
    else raise ArgumentError, "unknown operation #{op}"
    end
  end
end
