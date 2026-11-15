# did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
# verification as a VH-Log log, so it is verified by VHLog with the did:vh
# specialisation. This module adds the DID syntax, the srcLog/srcWitness and DID
# URL rules, the resolution options, and DID Resolution metadata and errors.
module VHLog
  module DidVh
    extend self
    METHOD = 'did:vh:1.0'.freeze
    PREFIX = 'did:vh:'.freeze
    METHOD_SYNTAX = /\Adid:vh:(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/
    SCID = /\A[1-9A-HJ-NP-Za-km-z]{46}\z/
    # Unicode White_Space (profile §3).
    WHITESPACE = /\A[\t\n\v\f\r \u0085   -     　]\z/
    SELECTORS = %w[versionId versionTime versionNumber].freeze
    URL_PARAMETERS = %w[src versionId versionTime versionNumber].freeze
    OPTION_ONLY = %w[didLog didWitness srcLog srcWitness checkWatchers extraWatchers minCopies includeDidLog].freeze
    ERROR_MAP = {'not-found'=>'notFound', 'invalid-option'=>'invalidOptions', 'fork-detected'=>'logForked',
                 'min-copies-not-met'=>'insufficientCopies', 'unsupported-log-version'=>'featureNotSupported'}.freeze

    # A did:vh error: a DID Resolution error code, and the VH-Log error report behind it, if any.
    class Error < StandardError
      attr_reader :code, :vh_log
      def initialize(code, message, vh_log = nil)
        super(message)
        @code = code
        @vh_log = vh_log
      end
    end

    # The SCID of a did:vh DID, or nil if `did` does not match the ABNF.
    def parse_did(did)
      return nil unless did.is_a?(String) && did.start_with?(PREFIX)
      scid = did[PREFIX.length..]
      SCID.match?(scid) ? scid : nil
    end

    # The did:vh specialisation: `method` instead of `logVersion`, a closed
    # parameter set, and state.id = did:vh:<SCID> in every entry. With
    # `expected_scid`, the log's SCID must also be that of the DID being resolved.
    def specialisation(expected_scid = nil)
      state = lambda do |s, scid, n|
        VHLog.fail!('invalid-state', n) if expected_scid && scid != expected_scid
        VHLog.fail!('invalid-state', n) unless s['id'] == PREFIX + scid
      end
      {param: 'method', versions: [METHOD], syntax: METHOD_SYNTAX, extra: [], state: state}
    end

    # Creates a did:vh DID log. `method` and `scid` are added to the parameters if absent.
    def create(input)
      created = VHLog.create({'state'=>input['document'], 'parameters'=>input['parameters'] || {},
                              'versionTime'=>input['versionTime'], 'signers'=>input['signers']}, 'method', METHOD)
      {'log'=>created['log'], 'did'=>PREFIX + created['scid'], 'scid'=>created['scid'], 'versionId'=>created['versionId']}
    end

    # Appends an entry; deactivate with parameters {"deactivated": true}.
    def update(input)
      VHLog.update({'log'=>input['log'], 'state'=>input['document'], 'parameters'=>input['parameters'] || {},
                    'versionTime'=>input['versionTime'], 'signers'=>input['signers']})
    end

    # ------------------------------------------------------------ shared URL checks

    # Percent-decodes `s` as UTF-8, or nil if an escape or the UTF-8 is malformed.
    def percent_decode(s)
      out = ''.b
      i = 0
      while i < s.length
        if s[i] == '%'
          hex = s[i + 1, 2]
          return nil unless hex && /\A[0-9A-Fa-f]{2}\z/.match?(hex)
          out << hex.to_i(16).chr
          i += 3
        else
          out << s[i].b
          i += 1
        end
      end
      out.force_encoding('UTF-8')
      out.valid_encoding? ? out : nil
    end

    def loopback_host?(host)
      return true if host == 'localhost' || host == '[::1]'
      parts = host.split('.', -1)
      parts.length == 4 && parts[0] == '127' && parts.all? { |p| /\A(0|[1-9][0-9]{0,2})\z/.match?(p) && p.to_i <= 255 }
    end

    def domain_name?(host)
      name = host.end_with?('.') ? host[0...-1] : host
      return false if name.empty? || name.length > 253
      labels = name.split('.', -1)
      return false if /\A[0-9]+\z/.match?(labels.last) # an IPv4 literal, or ends in a number
      labels.all? { |l| /\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/.match?(l) }
    end

    # Splits scheme:rest (profile §3 steps 1–2); nil unless printable ASCII with a scheme.
    def split_scheme(value)
      return nil unless value.is_a?(String) && /\A[\x21-\x7e]+\z/.match?(value)
      m = /\A([A-Za-z][A-Za-z0-9+.-]*):(.*)\z/m.match(value)
      m && [m[1].downcase, m[2]]
    end

    # Checks an http(s) authority (profile §3); returns the lowercased host, or nil.
    def check_authority(authority, scheme)
      return nil if authority.include?('@')
      port = nil
      if authority.start_with?('[')
        close = authority.index(']')
        return nil unless close
        host = authority[0..close]
        after = authority[(close + 1)..]
        unless after.empty?
          return nil unless after.start_with?(':')
          port = after[1..]
        end
      else
        host, colon, rest = authority.partition(':')
        port = rest unless colon.empty?
      end
      host = host.downcase
      return nil if port && !(/\A[0-9]{1,5}\z/.match?(port) && port.to_i <= 65_535)
      return (loopback_host?(host) ? host : nil) if scheme == 'http'
      !host.start_with?('[') && domain_name?(host) ? host : nil
    end

    # Checks the segments of a path starting with "/" (profile §3). With `strict`
    # (the src DID URL parameter), segments must also be non-empty and not start
    # or end with whitespace.
    def segments_ok?(path, strict)
      path[1..].split('/', -1).all? do |raw|
        segment = percent_decode(raw)
        next false if segment.nil? || segment == '.' || segment == '..' || segment.match?(%r{[/\\\x00]})
        next true unless strict
        !segment.empty? && !WHITESPACE.match?(segment[0]) && !WHITESPACE.match?(segment[-1])
      end
    end

    # ------------------------------------------------------------ references

    # Validates a srcLog or srcWitness reference (profile §3.1) and returns its
    # kind: web, loopback, file or other. Raises invalidOptions.
    def check_ref(ref)
      invalid = ->(why) { Error.new('invalidOptions', "reference #{ref.inspect}: #{why}") }
      scheme, rest = split_scheme(ref)
      raise invalid.call('not a printable-ASCII absolute URL') unless scheme
      raise invalid.call('must not have a fragment') if rest.include?('#')
      case scheme
      when 'https', 'http'
        raise invalid.call('missing authority') unless rest.start_with?('//')
        tail = rest[2..]
        stop = tail.index(%r{[/?]})
        authority = stop ? tail[0...stop] : tail
        path = (stop ? tail[stop..] : '').partition('?')[0]
        raise invalid.call('invalid host') unless check_authority(authority, scheme)
        raise invalid.call('must have a path') if path.empty?
        raise invalid.call('invalid path segment') unless segments_ok?(path, false)
        scheme == 'http' ? 'loopback' : 'web'
      when 'file'
        raise invalid.call('must not have a query') if rest.include?('?')
        if rest.start_with?('//')
          slash = rest.index('/', 2)
          raise invalid.call('file URL needs an absolute path') unless slash
          raise invalid.call('file URL host must be empty or localhost') unless ['', 'localhost'].include?(rest[2...slash].downcase)
          path = rest[slash..]
        else
          raise invalid.call('file URL needs an absolute path') unless rest.start_with?('/')
          path = rest
        end
        raise invalid.call('invalid path segment') unless segments_ok?(path, false)
        'file'
      else
        raise invalid.call('empty URL') if rest.empty?
        'other'
      end
    end

    # Validates a (percent-decoded) src DID URL parameter and derives srcLog and
    # srcWitness from it (profile §3.2). Raises invalidDidUrl.
    def src_references(src)
      invalid = ->(why) { Error.new('invalidDidUrl', "src #{src.inspect}: #{why}") }
      scheme, rest = split_scheme(src)
      raise invalid.call('not a printable-ASCII absolute URL') unless scheme
      raise invalid.call('must not have a query or fragment') if rest.include?('?') || rest.include?('#')
      raise invalid.call("#{scheme} is not allowed in a DID URL") if %w[http file].include?(scheme)
      raise invalid.call('not a hierarchical URL with an authority') if !rest.start_with?('//') || rest.length == 2 || rest[2] == '/'
      base = rest.end_with?('/') ? rest[0...-1] : rest
      if scheme == 'https'
        slash = base.index('/', 2)
        authority = slash ? base[2...slash] : base[2..]
        path = slash ? base[slash..] : ''
        raise invalid.call('invalid https host') unless check_authority(authority, 'https')
        raise invalid.call('invalid path segment') unless path.empty? || segments_ok?(path, true)
      end
      location = "#{scheme}:#{base}"
      {'srcLog'=>"#{location}/did.jsonl", 'srcWitness'=>"#{location}/did-witness.json"}
    end

    # Parses a did:vh DID URL as a dereferencer does (profile §4); returns
    # {did, options, fragment?}. Raises invalidDidUrl.
    def parse_did_url(did_url)
      invalid = ->(why) { Error.new('invalidDidUrl', "#{did_url.inspect}: #{why}") }
      raise invalid.call('not a string') unless did_url.is_a?(String)
      before_fragment, hash, fragment = did_url.partition('#')
      did, question, query = before_fragment.partition('?')
      raise invalid.call('not a did:vh DID') unless parse_did(did)
      seen = []
      options = {}
      unless question.empty?
        query.split('&', -1).each do |pair|
          raw_key, eq, raw_value = pair.partition('=')
          raise invalid.call("query parameter #{pair.inspect} has no value") if eq.empty?
          key, value = percent_decode(raw_key), percent_decode(raw_value)
          raise invalid.call('malformed percent-encoding') unless key && value
          raise invalid.call("#{key} is a resolution option, not a DID URL parameter") if OPTION_ONLY.include?(key)
          next unless URL_PARAMETERS.include?(key)
          raise invalid.call("#{key} given more than once") if seen.include?(key)
          seen << key
          case key
          when 'src' then options.merge!(src_references(value))
          when 'versionNumber'
            raise invalid.call('versionNumber must be a positive integer') unless /\A[1-9][0-9]{0,15}\z/.match?(value)
            options['versionNumber'] = value.to_i
          else options[key] = value
          end
        end
      end
      result = {'did'=>did, 'options'=>options}
      result['fragment'] = fragment unless hash.empty?
      result
    end

    # ------------------------------------------------------------ resolve

    def positive_integer?(v)
      VHLog.integer?(v) && v >= 1
    end

    # did:vh resolution options validation (profile §5, step 2).
    def validate_options(o, remote)
      invalid = ->(why) { Error.new('invalidOptions', why) }
      raise invalid.call('resolution options must be an object') unless o.is_a?(Hash)
      raise invalid.call('exactly one of didLog and srcLog must be given') if o.key?('didLog') == o.key?('srcLog')
      raise invalid.call('at most one of didWitness and srcWitness may be given') if o.key?('didWitness') && o.key?('srcWitness')
      raise invalid.call('didLog must be a string') if o.key?('didLog') && !o['didLog'].is_a?(String)
      raise invalid.call('didWitness must be an array') if o.key?('didWitness') && !o['didWitness'].is_a?(Array)
      %w[srcLog srcWitness].each do |key|
        next unless o.key?(key)
        kind = check_ref(o[key])
        raise invalid.call("#{key}: a resolver that serves other systems must not use local references") if remote && %w[file loopback].include?(kind)
      end
      raise invalid.call('at most one version selector may be given') if (o.keys & SELECTORS).length > 1
      raise invalid.call('versionId must be a string') if o.key?('versionId') && !o['versionId'].is_a?(String)
      raise invalid.call('versionTime must be a whole-second UTC ISO 8601 time') if o.key?('versionTime') && !VHLog.time(o['versionTime'])
      raise invalid.call('versionNumber must be a positive integer') if o.key?('versionNumber') && !positive_integer?(o['versionNumber'])
      if o.key?('checkWatchers')
        c = o['checkWatchers']
        raise invalid.call('checkWatchers must be a non-negative integer or "all"') unless c == 'all' || (VHLog.integer?(c) && c >= 0)
      end
      if o.key?('extraWatchers')
        w = o['extraWatchers']
        ok = w.is_a?(Array) && w.all? { |u| u.is_a?(String) && /\A[\x21-\x7e]+\z/.match?(u) && %r{\Ahttps://[^/?#]}.match?(u) }
        raise invalid.call('extraWatchers must be an array of https URLs') unless ok
      end
      raise invalid.call('minCopies must be a positive integer') if o.key?('minCopies') && !positive_integer?(o['minCopies'])
      raise invalid.call('includeDidLog must be a boolean') if o.key?('includeDidLog') && ![true, false].include?(o['includeDidLog'])
      o
    end

    def failure(error)
      details = {'title'=>error.code, 'detail'=>error.message}
      details['vhLog'] = error.vh_log if error.vh_log
      {'didResolutionMetadata'=>{'error'=>error.code, 'problemDetails'=>details}, 'didDocument'=>nil, 'didDocumentMetadata'=>{}}
    end

    # Integral JSON numbers are parsed as floats; did:vh returns them as integers.
    def int(v)
      v.is_a?(Float) && v == v.to_i ? v.to_i : v
    end

    # did:vh resolve(did, resolutionOptions) (profile §5). Offline: it verifies a
    # log passed in didLog (and didWitness), and returns featureNotSupported when
    # it would have to retrieve anything. `now` is the resolver's clock.
    def resolve(did, options, now: nil, remote: false)
      scid = parse_did(did)
      raise Error.new('invalidDid', "#{did.inspect} is not a did:vh DID") unless scid
      options = validate_options(options.nil? ? {} : options, remote)
      raise Error.new('featureNotSupported', 'this resolver does not retrieve srcLog references') if options.key?('srcLog')
      if options.fetch('checkWatchers', 0) != 0 || !options.fetch('extraWatchers', []).empty?
        raise Error.new('featureNotSupported', 'this resolver does not retrieve copies from watchers')
      end
      spec = specialisation(scid)
      now ||= Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
      log = options['didLog']
      # Whether the log needs witnessing does not depend on the witness file.
      # Without one, the first entry that needs it fails, which cuts it from entries.
      clock = VHLog.time(now) || VHLog.time(Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ'))
      unwitnessed = VHLog.verify_log(log, ABSENT, clock, spec)
      witnessed = unwitnessed[:failure]&.fetch('code') == 'witness-threshold-not-met' || unwitnessed[:entries].any? { |e| e[:rule] }
      if witnessed && options.key?('srcWitness')
        raise Error.new('featureNotSupported', 'this resolver does not retrieve srcWitness references')
      end
      request = {'log'=>log, 'now'=>now, 'options'=>options.slice(*SELECTORS, 'minCopies')}
      request['witness'] = options['didWitness'] if options.key?('didWitness')
      result = VHLog.resolve(request, spec)
      unless result['valid']
        error = result['error']
        raise Error.new(ERROR_MAP.fetch(error['code'], 'invalidDid'), error['message'], error)
      end
      partial = result['error']
      if (options.keys & SELECTORS).empty? && partial && partial['code'] == 'unsupported-log-version'
        # Entries after the last valid one may change the document or its keys (profile §5).
        raise Error.new('featureNotSupported', partial['message'], partial)
      end
      m = result['metadata']
      # A deactivated DID's document is not returned; earlier versions still are (profile §5).
      last = m['versionTime'] == m['updated']
      metadata = {'versionId'=>m['versionId'], 'versionTime'=>m['versionTime'], 'created'=>m['created'],
                  'updated'=>m['updated'], 'scid'=>m['scid'], 'deactivated'=>m['deactivated'], 'ttl'=>int(m['ttl'])}
      metadata['witness'] = m['witness'].merge('threshold'=>int(m['witness']['threshold'])) if m['witness']
      metadata['watchers'] = m['watchers']
      meta = {'contentType'=>'application/did+json'}
      meta['warnings'] = m['warnings'] unless m['warnings'].empty?
      if options['includeDidLog'] == true
        lines = VHLog.lines(log)
        valid = result['firstInvalidVersion'] ? result['firstInvalidVersion'] - 1 : lines.length
        meta['didLog'] = lines.take(valid).map { |l| l + "\n" }.join
        meta['didWitness'] = options.fetch('didWitness', []) if witnessed
      end
      {'didResolutionMetadata'=>meta, 'didDocument'=>m['deactivated'] && last ? nil : result['state'], 'didDocumentMetadata'=>metadata}
    rescue Error => e
      failure(e)
    end

    # Runs a block, turning a did:vh error into {valid: false, error}.
    def rejected
      {'valid'=>true}.merge(yield)
    rescue Error => e
      {'valid'=>false, 'error'=>e.code}
    end

    # The didvh-* driver operations (docs/interop-protocol.md, "did:vh operations").
    def dispatch(op, input)
      case op
      when 'didvh-create' then create(input)
      when 'didvh-update' then update(input)
      when 'didvh-resolve' then resolve(input['did'], input['options'], now: input['now'], remote: input['remote'] == true)
      when 'didvh-ref' then rejected { {'kind'=>check_ref(input['ref'])} }
      when 'didvh-src' then rejected { src_references(input['src']) }
      when 'didvh-did-url' then rejected { parse_did_url(input['didUrl']) }
      else raise ArgumentError, "unknown operation #{op}"
      end
    end
  end
end
