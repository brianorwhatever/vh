<?php
declare(strict_types=1);
namespace VHLog;

/** A did:vh error: a DID Resolution error code, and the VH-Log error report behind it, if any. */
final class DidVhError extends \RuntimeException {
    public function __construct(public readonly string $error, string $message, public readonly ?array $vhLog = null) {
        parent::__construct($message);
    }
}

/**
 * did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
 * verification as a VH-Log log, so it is verified by Log with the did:vh
 * specialisation. This class adds the DID syntax, the srcLog/srcWitness and DID
 * URL rules, the resolution options, and DID Resolution metadata and errors.
 */
final class DidVh {
    public const METHOD = 'did:vh:1.0';
    public const PREFIX = 'did:vh:';
    private const METHOD_SYNTAX = '/\Adid:vh:(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/D';
    /** Unicode White_Space (profile §3). */
    private const WHITESPACE = '[\x{9}-\x{D}\x{20}\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]';
    private const SELECTORS = ['versionId','versionTime','versionNumber'];
    private const URL_PARAMETERS = ['src','versionId','versionTime','versionNumber'];
    private const OPTION_ONLY = ['didLog','didWitness','srcLog','srcWitness','checkWatchers','extraWatchers','minCopies','includeDidLog'];
    private const ERROR_MAP = ['not-found'=>'notFound','invalid-option'=>'invalidOptions','fork-detected'=>'logForked',
        'min-copies-not-met'=>'insufficientCopies','unsupported-log-version'=>'featureNotSupported'];

    /** The SCID of a did:vh DID, or null if `$did` does not match the ABNF. */
    public static function parseDid(mixed $did): ?string {
        if (!is_string($did) || !str_starts_with($did,self::PREFIX)) return null;
        $scid=substr($did,strlen(self::PREFIX));
        return preg_match('/\A[1-9A-HJ-NP-Za-km-z]{46}\z/D',$scid) ? $scid : null;
    }

    /**
     * The did:vh specialisation: `method` instead of `logVersion`, a closed
     * parameter set, and state.id = did:vh:<SCID> in every entry. With
     * `$expectedScid`, the log's SCID must also be that of the DID being resolved.
     */
    public static function specialisation(?string $expectedScid=null): array {
        $state=function(object $state,string $scid,int $n) use ($expectedScid): void {
            if ($expectedScid!==null && $scid!==$expectedScid) throw new ProtocolError('invalid-state',$n);
            if (($state->id ?? null)!==self::PREFIX.$scid) throw new ProtocolError('invalid-state',$n);
        };
        return ['param'=>'method','versions'=>[self::METHOD],'syntax'=>self::METHOD_SYNTAX,'extra'=>[],'state'=>$state];
    }

    /** Creates a did:vh DID log. `method` and `scid` are added to the parameters if absent. */
    public static function create(object $input): array {
        $created=Log::create((object)['state'=>$input->document,'parameters'=>$input->parameters ?? (object)[],
            'versionTime'=>$input->versionTime,'signers'=>$input->signers],'method',self::METHOD);
        return ['log'=>$created['log'],'did'=>self::PREFIX.$created['scid'],'scid'=>$created['scid'],'versionId'=>$created['versionId']];
    }

    /** Appends an entry; deactivate with parameters {"deactivated": true}. */
    public static function update(object $input): array {
        return Log::update((object)['log'=>$input->log,'state'=>$input->document,'parameters'=>$input->parameters ?? (object)[],
            'versionTime'=>$input->versionTime,'signers'=>$input->signers]);
    }

    // ------------------------------------------------------------ shared URL checks

    /** Percent-decodes `$s` as UTF-8, or null if an escape or the UTF-8 is malformed. */
    public static function percentDecode(string $s): ?string {
        $out='';
        for ($i=0; $i<strlen($s); $i++) {
            if ($s[$i]==='%') {
                $hex=substr($s,$i+1,2);
                if (!preg_match('/\A[0-9A-Fa-f]{2}\z/D',$hex)) return null;
                $out.=chr(hexdec($hex)); $i+=2;
            } else $out.=$s[$i];
        }
        return mb_check_encoding($out,'UTF-8') ? $out : null;
    }

    private static function isLoopbackHost(string $host): bool {
        if ($host==='localhost' || $host==='[::1]') return true;
        $parts=explode('.',$host);
        if (count($parts)!==4 || $parts[0]!=='127') return false;
        foreach ($parts as $p) if (!preg_match('/\A(0|[1-9][0-9]{0,2})\z/D',$p) || (int)$p>255) return false;
        return true;
    }

    private static function isDomainName(string $host): bool {
        $name=str_ends_with($host,'.') ? substr($host,0,-1) : $host;
        if ($name==='' || strlen($name)>253) return false;
        $labels=explode('.',$name);
        if (preg_match('/\A[0-9]+\z/D',end($labels))) return false; // an IPv4 literal, or ends in a number
        foreach ($labels as $l) if (!preg_match('/\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\z/D',$l)) return false;
        return true;
    }

    /** Splits scheme:rest (profile §3 steps 1–2); null unless printable ASCII with a scheme. */
    private static function splitScheme(mixed $value): ?array {
        if (!is_string($value) || !preg_match('/\A[\x21-\x7e]+\z/D',$value)) return null;
        if (!preg_match('/\A([A-Za-z][A-Za-z0-9+.-]*):(.*)\z/Ds',$value,$m)) return null;
        return [strtolower($m[1]),$m[2]];
    }

    /** Checks an http(s) authority (profile §3); returns the lowercased host, or null. */
    private static function checkAuthority(string $authority,string $scheme): ?string {
        if (str_contains($authority,'@')) return null;
        $port=null;
        if (str_starts_with($authority,'[')) {
            $close=strpos($authority,']');
            if ($close===false) return null;
            $host=substr($authority,0,$close+1);
            $after=substr($authority,$close+1);
            if ($after!=='') {
                if (!str_starts_with($after,':')) return null;
                $port=substr($after,1);
            }
        } else {
            $colon=strpos($authority,':');
            $host=$colon===false ? $authority : substr($authority,0,$colon);
            if ($colon!==false) $port=substr($authority,$colon+1);
        }
        $host=strtolower($host);
        if ($port!==null && !(preg_match('/\A[0-9]{1,5}\z/D',$port) && (int)$port<=65535)) return null;
        if ($scheme==='http') return self::isLoopbackHost($host) ? $host : null;
        return !str_starts_with($host,'[') && self::isDomainName($host) ? $host : null;
    }

    /**
     * Checks the segments of a path starting with "/" (profile §3). With
     * `$strict` (the src DID URL parameter), segments must also be non-empty and
     * not start or end with whitespace.
     */
    private static function segmentsOk(string $path,bool $strict): bool {
        foreach (explode('/',substr($path,1)) as $raw) {
            $segment=self::percentDecode($raw);
            if ($segment===null || $segment==='.' || $segment==='..' || preg_match('~[/\\\\\x00]~',$segment)) return false;
            if ($strict && ($segment==='' || preg_match('/\A'.self::WHITESPACE.'|'.self::WHITESPACE.'\z/Du',$segment))) return false;
        }
        return true;
    }

    // ------------------------------------------------------------ references

    /** Validates a srcLog or srcWitness reference (profile §3.1); returns web, loopback, file or other. */
    public static function checkRef(mixed $ref): string {
        $invalid=fn(string $why)=>new DidVhError('invalidOptions','reference '.json_encode($ref).': '.$why);
        $parts=self::splitScheme($ref);
        if ($parts===null) throw $invalid('not a printable-ASCII absolute URL');
        [$scheme,$rest]=$parts;
        if (str_contains($rest,'#')) throw $invalid('must not have a fragment');
        if ($scheme==='https' || $scheme==='http') {
            if (!str_starts_with($rest,'//')) throw $invalid('missing authority');
            $tail=substr($rest,2);
            $stop=strcspn($tail,'/?');
            $authority=substr($tail,0,$stop);
            $path=explode('?',substr($tail,$stop),2)[0];
            if (self::checkAuthority($authority,$scheme)===null) throw $invalid('invalid host');
            if ($path==='') throw $invalid('must have a path');
            if (!self::segmentsOk($path,false)) throw $invalid('invalid path segment');
            return $scheme==='http' ? 'loopback' : 'web';
        }
        if ($scheme==='file') {
            if (str_contains($rest,'?')) throw $invalid('must not have a query');
            if (str_starts_with($rest,'//')) {
                $slash=strpos($rest,'/',2);
                if ($slash===false) throw $invalid('file URL needs an absolute path');
                if (!in_array(strtolower(substr($rest,2,$slash-2)),['','localhost'],true)) throw $invalid('file URL host must be empty or localhost');
                $path=substr($rest,$slash);
            } else {
                if (!str_starts_with($rest,'/')) throw $invalid('file URL needs an absolute path');
                $path=$rest;
            }
            if (!self::segmentsOk($path,false)) throw $invalid('invalid path segment');
            return 'file';
        }
        if ($rest==='') throw $invalid('empty URL');
        return 'other';
    }

    /** Validates a (percent-decoded) src DID URL parameter and derives srcLog and srcWitness (profile §3.2). */
    public static function srcReferences(mixed $src): array {
        $invalid=fn(string $why)=>new DidVhError('invalidDidUrl','src '.json_encode($src).': '.$why);
        $parts=self::splitScheme($src);
        if ($parts===null) throw $invalid('not a printable-ASCII absolute URL');
        [$scheme,$rest]=$parts;
        if (str_contains($rest,'?') || str_contains($rest,'#')) throw $invalid('must not have a query or fragment');
        if ($scheme==='http' || $scheme==='file') throw $invalid("$scheme is not allowed in a DID URL");
        if (!str_starts_with($rest,'//') || strlen($rest)===2 || $rest[2]==='/') throw $invalid('not a hierarchical URL with an authority');
        $base=str_ends_with($rest,'/') ? substr($rest,0,-1) : $rest;
        if ($scheme==='https') {
            $slash=strpos($base,'/',2);
            $authority=$slash===false ? substr($base,2) : substr($base,2,$slash-2);
            $path=$slash===false ? '' : substr($base,$slash);
            if (self::checkAuthority($authority,'https')===null) throw $invalid('invalid https host');
            if ($path!=='' && !self::segmentsOk($path,true)) throw $invalid('invalid path segment');
        }
        $location="$scheme:$base";
        return ['srcLog'=>"$location/did.jsonl",'srcWitness'=>"$location/did-witness.json"];
    }

    /** Parses a did:vh DID URL as a dereferencer does (profile §4); returns {did, options, fragment?}. */
    public static function parseDidUrl(mixed $didUrl): array {
        $invalid=fn(string $why)=>new DidVhError('invalidDidUrl',json_encode($didUrl).': '.$why);
        if (!is_string($didUrl)) throw $invalid('not a string');
        $hash=strpos($didUrl,'#');
        $beforeFragment=$hash===false ? $didUrl : substr($didUrl,0,$hash);
        $q=strpos($beforeFragment,'?');
        $did=$q===false ? $beforeFragment : substr($beforeFragment,0,$q);
        if (self::parseDid($did)===null) throw $invalid('not a did:vh DID');
        $seen=[]; $options=new \stdClass();
        if ($q!==false) {
            foreach (explode('&',substr($beforeFragment,$q+1)) as $pair) {
                $eq=strpos($pair,'=');
                if ($eq===false) throw $invalid("query parameter $pair has no value");
                $key=self::percentDecode(substr($pair,0,$eq)); $value=self::percentDecode(substr($pair,$eq+1));
                if ($key===null || $value===null) throw $invalid('malformed percent-encoding');
                if (in_array($key,self::OPTION_ONLY,true)) throw $invalid("$key is a resolution option, not a DID URL parameter");
                if (!in_array($key,self::URL_PARAMETERS,true)) continue;
                if (isset($seen[$key])) throw $invalid("$key given more than once");
                $seen[$key]=true;
                if ($key==='src') foreach (self::srcReferences($value) as $k=>$v) $options->$k=$v;
                elseif ($key==='versionNumber') {
                    if (!preg_match('/\A[1-9][0-9]{0,15}\z/D',$value)) throw $invalid('versionNumber must be a positive integer');
                    $options->versionNumber=(int)$value;
                } else $options->$key=$value;
            }
        }
        $result=['did'=>$did,'options'=>$options];
        if ($hash!==false) $result['fragment']=substr($didUrl,$hash+1);
        return $result;
    }

    // ------------------------------------------------------------ resolve

    private static function positiveInteger(mixed $v): bool { return Log::integer($v) && $v>=1; }

    /** did:vh resolution options validation (profile §5, step 2). */
    private static function validateOptions(mixed $o,bool $remote): object {
        $invalid=fn(string $why)=>new DidVhError('invalidOptions',$why);
        if (!is_object($o)) throw $invalid('resolution options must be an object');
        $has=fn(string $k)=>property_exists($o,$k);
        if ($has('didLog')===$has('srcLog')) throw $invalid('exactly one of didLog and srcLog must be given');
        if ($has('didWitness') && $has('srcWitness')) throw $invalid('at most one of didWitness and srcWitness may be given');
        if ($has('didLog') && !is_string($o->didLog)) throw $invalid('didLog must be a string');
        if ($has('didWitness') && !is_array($o->didWitness)) throw $invalid('didWitness must be an array');
        foreach (['srcLog','srcWitness'] as $key) {
            if (!$has($key)) continue;
            $kind=self::checkRef($o->$key);
            if ($remote && ($kind==='file' || $kind==='loopback')) throw $invalid("$key: a resolver that serves other systems must not use local references");
        }
        if (count(array_filter(self::SELECTORS,$has))>1) throw $invalid('at most one version selector may be given');
        if ($has('versionId') && !is_string($o->versionId)) throw $invalid('versionId must be a string');
        if ($has('versionTime') && Log::time($o->versionTime)===null) throw $invalid('versionTime must be a whole-second UTC ISO 8601 time');
        if ($has('versionNumber') && !self::positiveInteger($o->versionNumber)) throw $invalid('versionNumber must be a positive integer');
        if ($has('checkWatchers') && $o->checkWatchers!=='all' && !(Log::integer($o->checkWatchers) && $o->checkWatchers>=0)) {
            throw $invalid('checkWatchers must be a non-negative integer or "all"');
        }
        if ($has('extraWatchers')) {
            $ok=is_array($o->extraWatchers);
            if ($ok) foreach ($o->extraWatchers as $u) {
                if (!is_string($u) || !preg_match('/\A[\x21-\x7e]+\z/D',$u) || !preg_match('~\Ahttps://[^/?#]~',$u)) { $ok=false; break; }
            }
            if (!$ok) throw $invalid('extraWatchers must be an array of https URLs');
        }
        if ($has('minCopies') && !self::positiveInteger($o->minCopies)) throw $invalid('minCopies must be a positive integer');
        if ($has('includeDidLog') && !is_bool($o->includeDidLog)) throw $invalid('includeDidLog must be a boolean');
        return $o;
    }

    private static function failure(DidVhError $e): array {
        $details=['title'=>$e->error,'detail'=>$e->getMessage()];
        if ($e->vhLog!==null) $details['vhLog']=$e->vhLog;
        return ['didResolutionMetadata'=>['error'=>$e->error,'problemDetails'=>$details],'didDocument'=>null,'didDocumentMetadata'=>new \stdClass()];
    }

    /** Integral JSON numbers are parsed as floats; did:vh returns them as integers. */
    private static function int(mixed $v): mixed { return is_float($v) && floor($v)===$v ? (int)$v : $v; }

    /**
     * did:vh resolve(did, resolutionOptions) (profile §5). Offline: it verifies a
     * log passed in didLog (and didWitness), and returns featureNotSupported when
     * it would have to retrieve anything. `$now` is the resolver's clock.
     */
    public static function resolve(mixed $did,mixed $options,?string $now=null,bool $remote=false): array {
        try {
            $scid=self::parseDid($did);
            if ($scid===null) throw new DidVhError('invalidDid',json_encode($did).' is not a did:vh DID');
            $o=self::validateOptions($options ?? new \stdClass(),$remote);
            if (property_exists($o,'srcLog')) throw new DidVhError('featureNotSupported','this resolver does not retrieve srcLog references');
            if (($o->checkWatchers ?? 0)!=0 || count($o->extraWatchers ?? [])>0) {
                throw new DidVhError('featureNotSupported','this resolver does not retrieve copies from watchers');
            }
            $spec=self::specialisation($scid);
            $now??=gmdate('Y-m-d\TH:i:s\Z');
            $log=$o->didLog;
            // Whether the log needs witnessing does not depend on the witness file.
            // Without one, the first entry that needs it fails, which cuts it from entries.
            $unwitnessed=Log::verifyLog($log,null,Log::time($now) ?? time(),false,$spec);
            $witnessed=($unwitnessed['failure']['code'] ?? null)==='witness-threshold-not-met';
            foreach ($unwitnessed['entries'] as $e) if ($e['rule']!==null) $witnessed=true;
            if ($witnessed && property_exists($o,'srcWitness')) throw new DidVhError('featureNotSupported','this resolver does not retrieve srcWitness references');
            $vhOptions=new \stdClass();
            foreach ([...self::SELECTORS,'minCopies'] as $k) if (property_exists($o,$k)) $vhOptions->$k=$o->$k;
            $request=(object)['log'=>$log,'now'=>$now,'options'=>$vhOptions];
            if (property_exists($o,'didWitness')) $request->witness=$o->didWitness;
            $result=Log::resolve($request,$spec);
            if (!$result['valid']) {
                $error=$result['error'];
                throw new DidVhError(self::ERROR_MAP[$error['code']] ?? 'invalidDid',$error['message'],$error);
            }
            $selected=count(array_filter(self::SELECTORS,fn($k)=>property_exists($o,$k)))>0;
            $partial=$result['error'];
            if (!$selected && $partial!==null && $partial['code']==='unsupported-log-version') {
                // Entries after the last valid one may change the document or its keys (profile §5).
                throw new DidVhError('featureNotSupported',$partial['message'],$partial);
            }
            $m=$result['metadata'];
            $metadata=['versionId'=>$m['versionId'],'versionTime'=>$m['versionTime'],'created'=>$m['created'],'updated'=>$m['updated'],
                'scid'=>$m['scid'],'deactivated'=>$m['deactivated'],'ttl'=>self::int($m['ttl'])];
            if ($m['witness']!==null) $metadata['witness']=(object)['threshold'=>self::int($m['witness']->threshold),'witnesses'=>$m['witness']->witnesses];
            $metadata['watchers']=$m['watchers'];
            $meta=['contentType'=>'application/did+json'];
            if (count($m['warnings'])>0) $meta['warnings']=$m['warnings'];
            if (($o->includeDidLog ?? null)===true) {
                $lines=Log::lines($log);
                $valid=$result['firstInvalidVersion']===null ? count($lines) : $result['firstInvalidVersion']-1;
                $meta['didLog']=implode('',array_map(fn($l)=>$l."\n",array_slice($lines,0,$valid)));
                if ($witnessed) $meta['didWitness']=$o->didWitness ?? [];
            }
            // A deactivated DID's document is returned only for an explicit version selector (profile §5).
            return ['didResolutionMetadata'=>$meta,'didDocument'=>$m['deactivated'] && !$selected ? null : $result['state'],'didDocumentMetadata'=>$metadata];
        } catch (DidVhError $e) { return self::failure($e); }
    }

    /** Runs `$fn`, turning a did:vh error into {valid: false, error}. */
    private static function rejected(callable $fn): array {
        try { return ['valid'=>true,...$fn()]; } catch (DidVhError $e) { return ['valid'=>false,'error'=>$e->error]; }
    }

    /** The didvh-* driver operations (docs/interop-protocol.md, "did:vh operations"). */
    public static function dispatch(string $op,object $input): mixed {
        return match ($op) {
            'didvh-create'=>self::create($input),
            'didvh-update'=>self::update($input),
            'didvh-resolve'=>self::resolve($input->did ?? null,$input->options ?? null,$input->now ?? null,($input->remote ?? false)===true),
            'didvh-ref'=>self::rejected(fn()=>['kind'=>self::checkRef($input->ref ?? null)]),
            'didvh-src'=>self::rejected(fn()=>self::srcReferences($input->src ?? null)),
            'didvh-did-url'=>self::rejected(fn()=>self::parseDidUrl($input->didUrl ?? null)),
            default=>throw new \InvalidArgumentException('unknown operation '.$op)
        };
    }
}
