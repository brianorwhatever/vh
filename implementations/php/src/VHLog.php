<?php
declare(strict_types=1);
namespace VHLog;

final class ProtocolError extends \RuntimeException {
    public array $report;
    public function __construct(string $code, ?int $version = null, ?array $fork = null) {
        parent::__construct($code);
        $this->report = ['code'=>$code, 'version'=>$version, 'message'=>$code];
        if ($fork !== null) $this->report['fork'] = $fork;
    }
}
/** VH-Log profile 0. JSON objects remain objects, including empty objects. */
final class Log {
    private const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    private static function error(string $code, ?int $version = null, ?array $fork = null): never {
        throw new ProtocolError($code, $version, $fork);
    }
    public static function parse(string $text): mixed {
        $v = json_decode($text, false, 512, JSON_THROW_ON_ERROR);
        return self::normalize($v);
    }
    private static function normalize(mixed $v): mixed {
        if (is_object($v)) { foreach ($v as $k=>$x) $v->$k = self::normalize($x); }
        elseif (is_array($v)) $v = array_map(self::normalize(...), $v);
        elseif (is_int($v) || is_float($v)) {
            $v = (float)$v;
            if (!is_finite($v)) throw new \InvalidArgumentException('non-finite JSON number');
        }
        return $v;
    }
    private static function json(mixed $v): string {
        return json_encode($v, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS);
    }
    private static function number(float $v): string {
        if (!is_finite($v)) throw new \InvalidArgumentException('non-finite number');
        if ($v == 0) return '0';
        $sign = $v < 0 ? '-' : '';
        $parts = explode('e',strtolower(self::json(abs($v))));
        $mantissa = explode('.',$parts[0]);
        $digits = rtrim(implode('',$mantissa),'0');
        $point = strlen($mantissa[0]) + (int)($parts[1] ?? 0);
        while (str_starts_with($digits,'0')) { $digits = substr($digits,1); $point--; }
        if ($point > 0 && $point <= 21) {
            $s = strlen($digits) <= $point ? str_pad($digits,$point,'0') : substr($digits,0,$point).'.'.substr($digits,$point);
        } elseif ($point <= 0 && $point > -6) $s = '0.'.str_repeat('0',-$point).$digits;
        else { $e = $point-1; $s = $digits[0].(strlen($digits)>1 ? '.'.substr($digits,1) : '').'e'.($e>=0 ? '+' : '').$e; }
        return $sign.$s;
    }
    public static function jcs(mixed $v): string {
        if (is_object($v)) {
            $keys = array_keys(get_object_vars($v));
            usort($keys,fn($a,$b)=>strcmp(mb_convert_encoding((string)$a,'UTF-16BE','UTF-8'),mb_convert_encoding((string)$b,'UTF-16BE','UTF-8')));
            return '{'.implode(',',array_map(fn($k)=>self::json((string)$k).':'.self::jcs($v->{(string)$k}),$keys)).'}';
        }
        if (is_array($v)) return '['.implode(',',array_map(self::jcs(...),$v)).']';
        if (is_float($v) || is_int($v)) return self::number((float)$v);
        return self::json($v);
    }
    public static function encode(string $bytes): string {
        $digits = []; $zeros = 0;
        while ($zeros < strlen($bytes) && $bytes[$zeros] === "\0") $zeros++;
        for ($i=$zeros; $i<strlen($bytes); $i++) {
            $carry = ord($bytes[$i]);
            foreach ($digits as &$d) { $carry += $d*256; $d = $carry%58; $carry = intdiv($carry,58); }
            unset($d);
            while ($carry) { $digits[] = $carry%58; $carry = intdiv($carry,58); }
        }
        return str_repeat('1',$zeros).implode('',array_map(fn($d)=>self::ALPHABET[$d],array_reverse($digits)));
    }
    public static function decode(mixed $s): ?string {
        if (!is_string($s)) return null;
        $bytes=[]; $zeros=0;
        while ($zeros<strlen($s) && $s[$zeros]==='1') $zeros++;
        for ($i=$zeros;$i<strlen($s);$i++) {
            $carry=strpos(self::ALPHABET,$s[$i]);
            if ($carry===false) return null;
            foreach ($bytes as &$b) { $carry += $b*58; $b=$carry%256; $carry=intdiv($carry,256); }
            unset($b);
            while ($carry) { $bytes[]=$carry%256; $carry=intdiv($carry,256); }
        }
        return str_repeat("\0",$zeros).implode('',array_map(chr(...),array_reverse($bytes)));
    }
    public static function hash(string $s): string { return self::encode("\x12\x20".hash('sha256',$s,true)); }
    private static function checkHash(mixed $s): string {
        $b=self::decode($s);
        if ($b===null) return 'not-base58';
        return strlen($b)===34 && str_starts_with($b,"\x12\x20") ? 'ok' : 'unsupported-algorithm';
    }
    public static function publicKey(mixed $mk): ?string {
        if (!is_string($mk) || !str_starts_with($mk,'z')) return null;
        $b=self::decode(substr($mk,1));
        return $b!==null && strlen($b)===34 && str_starts_with($b,"\xed\x01") ? substr($b,2) : null;
    }
    private static function keypair(string $seed): string {
        if (!preg_match('/\A[0-9a-fA-F]{64}\z/D',$seed)) throw new \InvalidArgumentException('seed must be 32-byte hex');
        return sodium_crypto_sign_seed_keypair(hex2bin($seed));
    }
    public static function multikey(string $seed): string { return 'z'.self::encode("\xed\x01".sodium_crypto_sign_publickey(self::keypair($seed))); }
    private static function methodKey(mixed $vm): ?string {
        if (!is_string($vm) || !preg_match('/\Adid:key:([^#]+)#(.+)\z/D',$vm,$m)) return null;
        return $m[1]===$m[2] && self::publicKey($m[1])!==null ? $m[1] : null;
    }
    private static function signingInput(mixed $document, object $config): string {
        return hash('sha256',self::jcs($config),true).hash('sha256',self::jcs($document),true);
    }
    public static function sign(mixed $document,string $seed,?object $options=null): object {
        $options ??= (object)[]; $mk=self::multikey($seed);
        $config=(object)['type'=>'DataIntegrityProof','cryptosuite'=>'eddsa-jcs-2022','verificationMethod'=>$options->verificationMethod ?? "did:key:$mk#$mk"];
        if (property_exists($options,'created')) $config->created=$options->created;
        $config->proofPurpose='assertionMethod';
        $signature=sodium_crypto_sign_detached(self::signingInput($document,$config),sodium_crypto_sign_secretkey(self::keypair($seed)));
        $config->proofValue='z'.self::encode($signature);
        return $config;
    }
    public static function verify(mixed $document,mixed $proof): bool {
        if (!is_object($proof) || ($proof->type ?? null)!=='DataIntegrityProof' || ($proof->cryptosuite ?? null)!=='eddsa-jcs-2022' || ($proof->proofPurpose ?? null)!=='assertionMethod') return false;
        $mk=self::methodKey($proof->verificationMethod ?? null); $v=$proof->proofValue ?? null;
        if ($mk===null || !is_string($v) || !str_starts_with($v,'z')) return false;
        $sig=self::decode(substr($v,1));
        if ($sig===null || strlen($sig)!==64) return false;
        $config=clone $proof; unset($config->proofValue);
        return sodium_crypto_sign_verify_detached($sig,self::signingInput($document,$config),self::publicKey($mk));
    }
    private static function withoutProof(object $e): object { $v=clone $e; unset($v->proof); return $v; }
    public static function scid(object $e): string { return self::hash(self::jcs(self::withoutProof($e))); }
    public static function entryHash(object $e,string $previous): string {
        $v=self::withoutProof($e); $v->versionId=$previous;
        return self::hash(self::jcs($v));
    }
    private static function lines(string $log): array { $ls=explode("\n",$log); if (end($ls)==='') array_pop($ls); return $ls; }
    public static function create(object $input): array {
        $p=clone $input->parameters;
        if (!property_exists($p,'logVersion')) $p->logVersion='vh-log:1.0';
        if (!property_exists($p,'scid')) $p->scid='{SCID}';
        $e=(object)['versionId'=>'{SCID}','versionTime'=>$input->versionTime,'parameters'=>$p,'state'=>$input->state];
        $id=self::scid($e); $e=self::parse(str_replace('{SCID}',$id,self::json($e)));
        $e->versionId='1-'.self::entryHash($e,$id);
        $e->proof=array_map(fn($s)=>self::sign($e,$s,(object)['created'=>$input->versionTime]),$input->signers);
        return ['log'=>self::json($e)."\n",'scid'=>$id,'versionId'=>$e->versionId];
    }
    public static function update(object $input): array {
        $ls=self::lines($input->log); $previous=self::parse(end($ls))->versionId;
        $e=(object)['versionId'=>$previous,'versionTime'=>$input->versionTime,'parameters'=>$input->parameters ?? (object)[],'state'=>$input->state];
        $e->versionId=((int)explode('-',$previous)[0]+1).'-'.self::entryHash($e,$previous);
        $e->proof=array_map(fn($s)=>self::sign($e,$s,(object)['created'=>$input->versionTime]),$input->signers);
        return ['log'=>$input->log.(str_ends_with($input->log,"\n") ? '' : "\n").self::json($e)."\n",'versionId'=>$e->versionId];
    }
    public static function time(mixed $v): ?int {
        if (!is_string($v) || !preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:Z|\+00:00)\z/D',$v,$m)) return null;
        [$y,$mo,$d,$h,$mi,$s]=array_map(intval(...),array_slice($m,1));
        $leap=($y%4===0 && $y%100!==0) || $y%400===0;
        $days=[31,$leap ? 29 : 28,31,30,31,30,31,31,30,31,30,31];
        if ($mo<1 || $mo>12 || $d<1 || $d>$days[$mo-1] || $h>23 || $mi>59 || $s>59) return null;
        return (new \DateTimeImmutable($v))->getTimestamp();
    }
    private static function integer(mixed $v): bool { return (is_float($v) || is_int($v)) && is_finite((float)$v) && floor($v)===$v || is_int($v); }
    private static function strings(mixed $v): bool { return is_array($v) && count(array_filter($v,is_string(...)))===count($v); }
    private static function parameters(object $raw,?object $previous,int $n): object {
        foreach ($raw as $v) if ($v===null) self::error('invalid-parameter',$n);
        if (($previous===null && !property_exists($raw,'logVersion')) || (property_exists($raw,'logVersion') && $raw->logVersion!=='vh-log:1.0')) self::error('unsupported-log-version',$n);
        if ($previous!==null ? property_exists($raw,'scid') : (!is_string($raw->scid ?? null) || !property_exists($raw,'updateKeys'))) self::error('invalid-parameter',$n);
        if (property_exists($raw,'updateKeys')) {
            if (!self::strings($raw->updateKeys)) self::error('invalid-parameter',$n);
            foreach ($raw->updateKeys as $k) if (self::publicKey($k)===null) self::error('invalid-parameter',$n);
        }
        if (property_exists($raw,'nextKeyHashes')) {
            if (!self::strings($raw->nextKeyHashes)) self::error('invalid-parameter',$n);
            foreach ($raw->nextKeyHashes as $h) if (self::checkHash($h)!=='ok') self::error('invalid-parameter',$n);
        }
        $p=$previous===null ? (object)['nextKeyHashes'=>[],'witness'=>null,'watchers'=>[],'ttl'=>3600] : clone $previous;
        foreach (['logVersion','scid','updateKeys','nextKeyHashes','witness','watchers','ttl'] as $k) if (property_exists($raw,$k)) $p->$k=$raw->$k;
        $p->deactivated=$raw->deactivated ?? false;
        if (property_exists($raw,'witness')) {
            $w=$raw->witness;
            if (!is_object($w)) self::error('invalid-parameter',$n);
            if (count(get_object_vars($w))===0) $p->witness=null;
            else {
                $ws=$w->witnesses ?? null;
                if (!is_array($ws) || count($ws)===0) self::error('invalid-parameter',$n);
                $ids=[];
                foreach ($ws as $x) {
                    if (!is_object($x) || !is_string($x->id ?? null) || !str_starts_with($x->id,'did:key:') || self::publicKey(substr($x->id,8))===null) self::error('invalid-parameter',$n);
                    $ids[]=$x->id;
                }
                if (count(array_unique($ids))!==count($ids) || !self::integer($w->threshold ?? null) || $w->threshold<1 || $w->threshold>count($ids)) self::error('invalid-parameter',$n);
                $p->witness=(object)['threshold'=>$w->threshold,'witnesses'=>$ws];
            }
        }
        if (property_exists($raw,'watchers')) {
            if (!self::strings($raw->watchers)) self::error('invalid-parameter',$n);
            foreach ($raw->watchers as $u) if (!preg_match('/\A[\x21-\x7e]+\z/D',$u) || !preg_match('~\Ahttps?://[^/?#]~',$u)) self::error('invalid-parameter',$n);
        }
        if (!is_bool($p->deactivated) || !self::integer($p->ttl) || $p->ttl<0 || $p->ttl>2147483648) self::error('invalid-parameter',$n);
        if ($previous!==null && count($previous->nextKeyHashes)>0) {
            if (!property_exists($raw,'updateKeys') || !property_exists($raw,'nextKeyHashes')) self::error('prerotation-violation',$n);
            foreach ($raw->updateKeys as $key) if (!in_array(self::hash($key),$previous->nextKeyHashes,true)) self::error('prerotation-violation',$n);
        }
        return $p;
    }
    private static function verifyEntry(object $e,?array $previous,int $now): array {
        $n=$previous===null ? 1 : $previous['n']+1;
        if ($previous!==null && $previous['p']->deactivated) self::error('entry-after-deactivation',$n);
        $keys=array_keys(get_object_vars($e)); sort($keys);
        if ($keys!==['parameters','proof','state','versionId','versionTime'] || !is_string($e->versionId) || !is_string($e->versionTime) || !is_object($e->parameters) || !is_object($e->state) || !is_array($e->proof)) self::error('invalid-entry',$n);
        $p=self::parameters($e->parameters,$previous['p'] ?? null,$n);
        $active=$previous===null || count($previous['p']->nextKeyHashes)>0 ? $p->updateKeys : $previous['p']->updateKeys;
        $rule=$previous===null || (property_exists($e->parameters,'witness') && $previous['p']->witness===null) ? $p->witness : $previous['p']->witness;
        if (count($e->proof)===0) self::error('invalid-proof',$n);
        foreach ($e->proof as $proof) {
            $mk=is_object($proof) ? self::methodKey($proof->verificationMethod ?? null) : null;
            if ($mk===null) self::error('invalid-proof',$n);
            if (!in_array($mk,$active,true)) self::error('unauthorized-key',$n);
            if (!self::verify(self::withoutProof($e),$proof)) self::error('invalid-proof',$n);
        }
        if (!preg_match('/\A([1-9][0-9]*)-([^-]+)\z/D',$e->versionId,$m) || (float)$m[1]!== (float)$n) self::error('invalid-version-id',$n);
        $check=self::checkHash($m[2]);
        if ($check==='not-base58') self::error('invalid-version-id',$n);
        if ($check!=='ok') self::error('invalid-hash-algorithm',$n);
        if (self::entryHash($e,$previous===null ? $p->scid : $previous['e']->versionId)!==$m[2]) self::error('entry-hash-mismatch',$n);
        $time=self::time($e->versionTime);
        if ($time===null || ($previous!==null && $time<=$previous['time'])) self::error('invalid-version-time',$n);
        if ($time>$now+300) self::error('future-version-time',$n);
        if ($previous===null) {
            $check=self::checkHash($p->scid);
            if ($check==='unsupported-algorithm') self::error('invalid-hash-algorithm',$n);
            if ($check!=='ok') self::error('scid-mismatch',$n);
            $rest=self::withoutProof($e); $rest->versionId='{SCID}';
            $rest=self::parse(str_replace($p->scid,'{SCID}',self::json($rest)));
            if (self::scid($rest)!==$p->scid) self::error('scid-mismatch',$n);
        }
        return ['e'=>$e,'p'=>$p,'n'=>$n,'time'=>$time,'rule'=>$rule];
    }
    public static function verifyLog(string $log,mixed $witness,int $now,bool $hasWitness=true): array {
        $lines=self::lines($log); $entries=[]; $failure=null;
        if (count($lines)===0) return ['entries'=>[],'lines'=>[],'failure'=>(new ProtocolError('invalid-log'))->report];
        foreach ($lines as $i=>$line) {
            try {
                try { $e=self::parse($line); } catch (\JsonException | \InvalidArgumentException) { self::error('invalid-log',$i+1); }
                if (!is_object($e)) self::error('invalid-log',$i+1);
                $entries[]=self::verifyEntry($e,count($entries)>0 ? $entries[count($entries)-1] : null,$now);
            } catch (ProtocolError $error) { $failure=$error->report; break; }
        }
        foreach ($entries as $i=>$entry) {
            $rule=$entry['rule']; if ($rule===null) continue;
            $file=$hasWitness ? $witness : []; $code=null;
            $valid=is_array($file);
            if ($valid) foreach ($file as $r) if (!is_object($r) || !is_string($r->versionId ?? null) || !is_array($r->proof ?? null)) { $valid=false; break; }
            if (!$valid) $code='invalid-witness-file';
            else {
                $allowed=array_map(fn($w)=>$w->id,$rule->witnesses); $ids=[];
                foreach ($file as $r) {
                    $index=null;
                    foreach ($entries as $j=>$x) if ($x['e']->versionId===$r->versionId) { $index=$j; break; }
                    if ($index===null || $index<$i) continue;
                    foreach ($r->proof as $proof) {
                        $mk=is_object($proof) ? self::methodKey($proof->verificationMethod ?? null) : null;
                        $id='did:key:'.$mk;
                        if ($mk!==null && in_array($id,$allowed,true) && self::verify((object)['versionId'=>$r->versionId],$proof)) $ids[$id]=true;
                    }
                }
                if (count($ids)<$rule->threshold) $code='witness-threshold-not-met';
            }
            if ($code!==null) { $failure=(new ProtocolError($code,$i+1))->report; $entries=array_slice($entries,0,$i); break; }
        }
        return ['entries'=>$entries,'lines'=>$lines,'failure'=>$failure];
    }
    private static function lineValue(?string $line): mixed {
        if ($line===null) return null;
        try { return self::parse($line); } catch (\JsonException | \InvalidArgumentException) { return null; }
    }
    private static function lineId(?string $line): ?string { $v=self::lineValue($line); return is_object($v) && is_string($v->versionId ?? null) ? $v->versionId : null; }
    private static function retained(array $v,string $source,mixed $id,array &$warnings): void {
        if (!is_string($id) || !preg_match('/\A([1-9][0-9]*)-/',$id,$m)) self::error('invalid-option');
        $n=(int)$m[1];
        if (count($v['entries'])<$n) $warnings[]=['code'=>'retained-version-not-found','message'=>'retained version not found'];
        elseif ($v['entries'][$n-1]['e']->versionId!==$id) self::error('fork-detected',$n,['version'=>$n,'copies'=>[['source'=>'retained','versionId'=>$id],['source'=>$source,'versionId'=>$v['entries'][$n-1]['e']->versionId]]]);
    }
    private static function result(array $v,object $options,array $warnings,?array $copies=null): array {
        ['entries'=>$entries,'lines'=>$lines,'failure'=>$failure]=$v; $target=null;
        if (property_exists($options,'versionId')) {
            foreach ($entries as $e) if ($e['e']->versionId===$options->versionId) { $target=$e; break; }
            if ($target===null) foreach (array_slice($lines,count($entries)) as $l) if (self::lineId($l)===$options->versionId) self::error($failure['code'],$failure['version']);
        } elseif (property_exists($options,'versionNumber')) {
            $n=(int)$options->versionNumber; $target=$entries[$n-1] ?? null;
            if ($target===null && $n<=count($lines)) self::error($failure['code'],$failure['version']);
        } elseif (property_exists($options,'versionTime')) {
            $time=self::time($options->versionTime);
            if ($failure!==null) {
                $e=self::lineValue($lines[count($entries)] ?? null);
                $invalidTime=is_object($e) ? self::time($e->versionTime ?? null) : null;
                if ($invalidTime!==null && $invalidTime<=$time) self::error($failure['code'],$failure['version']);
            }
            foreach (array_reverse($entries) as $e) if ($e['time']<=$time) { $target=$e; break; }
        } else $target=end($entries);
        if ($target===null) self::error('not-found');
        $first=$entries[0]; $last=end($entries);
        if ($failure!==null) $warnings[]=['code'=>'invalid-entries','message'=>$failure['message']];
        $meta=['versionId'=>$target['e']->versionId,'versionTime'=>$target['e']->versionTime,'versionNumber'=>$target['n'],
            'created'=>$first['e']->versionTime,'updated'=>$last['e']->versionTime,'scid'=>$first['p']->scid,'deactivated'=>$last['p']->deactivated,
            'ttl'=>$last['p']->ttl,'witness'=>$last['p']->witness,'watchers'=>$last['p']->watchers,'updateKeys'=>$target['p']->updateKeys,
            'nextKeyHashes'=>$target['p']->nextKeyHashes,'warnings'=>$warnings];
        if ($copies!==null) $meta['copies']=$copies;
        return ['valid'=>true,'state'=>$target['e']->state,'metadata'=>$meta,'firstInvalidVersion'=>$failure!==null ? count($entries)+1 : null,'error'=>$failure];
    }
    private static function resolveCopies(object $input,int $now,object $options): array {
        $primary=(object)['source'=>'primary','log'=>$input->log];
        if (property_exists($input,'witness')) $primary->witness=$input->witness;
        $all=[$primary,...($input->copies ?? [])]; $warnings=[]; $status=[]; $cache=[];
        $get=function(int $i) use (&$cache,$all,$now): array {
            return $cache[$i] ??= self::verifyLog($all[$i]->log,$all[$i]->witness ?? null,$now,property_exists($all[$i],'witness'));
        };
        $invalid=function(int $i) use (&$status,&$warnings,$all): void {
            $status[$i]='invalid'; $warnings[]=['code'=>'copy-invalid','source'=>$all[$i]->source,'message'=>'copy fails verification'];
        };
        foreach ($all as $i=>$c) if (property_exists($c,'unavailable')) {
            $status[$i]='unavailable'; $warnings[]=['code'=>'copy-unavailable','source'=>$c->source,'message'=>$c->unavailable];
        }
        $ref=null;
        foreach ($all as $i=>$c) {
            if (isset($status[$i])) continue;
            if ($get($i)['failure']===null) { $ref=$i; break; }
            $invalid($i);
        }
        if ($ref===null) return ['valid'=>false,'error'=>$get(0)['failure']];
        $matched=[$ref=>true];
        foreach ($all as $i=>$c) {
            if (isset($status[$i]) || isset($matched[$i])) continue;
            $r=$get($ref); $v=$get($i); $rl=$r['lines']; $cl=$v['lines'];
            if (count($cl)===0) { $invalid($i); continue; }
            $same=count($cl)<=count($rl) && self::lineId(end($cl))===$r['entries'][count($cl)-1]['e']->versionId;
            $extends=count($cl)>count($rl) && self::lineId($cl[count($rl)-1])===$r['entries'][count($rl)-1]['e']->versionId;
            if ($same) $matched[$i]=true;
            elseif ($extends && $v['failure']===null) { $matched[$i]=true; $ref=$i; }
            elseif ($v['failure']!==null) $invalid($i);
            else {
                $k=0; while ($k<min(count($rl),count($cl)) && self::lineId($rl[$k])===self::lineId($cl[$k])) $k++;
                self::error('fork-detected',$k+1,['version'=>$k+1,'copies'=>[['source'=>$all[$ref]->source,'versionId'=>self::lineId($rl[$k] ?? null) ?? ''],['source'=>$c->source,'versionId'=>self::lineId($cl[$k] ?? null) ?? '']]]);
            }
        }
        $r=$get($ref);
        if (property_exists($input,'retainedVersionId')) self::retained($r,$all[$ref]->source,$input->retainedVersionId,$warnings);
        $copies=[];
        foreach ($all as $i=>$c) {
            $report=['source'=>$c->source];
            if (isset($status[$i])) {
                $report['status']=$status[$i];
                if ($status[$i]!=='unavailable') { $ls=$get($i)['lines']; $id=self::lineId(count($ls)>0 ? end($ls) : null); if ($id!==null) $report['versionId']=$id; }
            } else {
                $ls=$get($i)['lines']; $behind=count($ls)<count($r['lines']);
                $report['status']=$behind ? 'behind' : 'current'; $report['versionId']=self::lineId(end($ls));
                if ($behind) $warnings[]=['code'=>'copy-behind','source'=>$c->source,'message'=>'copy is behind'];
            }
            $copies[]=$report;
        }
        $usable=count(array_filter($copies,fn($c)=>in_array($c['status'],['current','behind'],true)));
        if ($usable<($options->minCopies ?? 1)) self::error('min-copies-not-met');
        return self::result($r,$options,$warnings,$copies);
    }
    public static function resolve(object $input): array {
        try {
            $now=self::time($input->now ?? null);
            if ($now===null) self::error('invalid-option');
            $options=$input->options ?? (object)[];
            if (!is_object($options)) self::error('invalid-option');
            $keys=array_keys(get_object_vars($options));
            if (count(array_diff($keys,['versionId','versionTime','versionNumber','minCopies']))>0 || count(array_intersect($keys,['versionId','versionTime','versionNumber']))>1) self::error('invalid-option');
            if (property_exists($options,'versionId') && !is_string($options->versionId)) self::error('invalid-option');
            if (property_exists($options,'versionTime') && self::time($options->versionTime)===null) self::error('invalid-option');
            foreach (['versionNumber','minCopies'] as $k) if (property_exists($options,$k) && (!self::integer($options->$k) || $options->$k<1)) self::error('invalid-option');
            if (property_exists($input,'copies') || ($options->minCopies ?? 1)>1) return self::resolveCopies($input,$now,$options);
            $v=self::verifyLog($input->log,$input->witness ?? null,$now,property_exists($input,'witness'));
            if (count($v['entries'])===0) return ['valid'=>false,'error'=>$v['failure']];
            $warnings=[];
            if (property_exists($input,'retainedVersionId')) self::retained($v,'primary',$input->retainedVersionId,$warnings);
            return self::result($v,$options,$warnings);
        } catch (ProtocolError $e) { return ['valid'=>false,'error'=>$e->report]; }
    }
    public static function dispatch(string $op,object $input): mixed {
        return match ($op) {
            'jcs'=>['output'=>self::jcs(self::parse($input->text))],
            'hash'=>['output'=>self::hash($input->data)],
            'key-hash'=>['output'=>self::hash($input->multikey)],
            'multikey'=>['multikey'=>self::multikey($input->seed)],
            'scid'=>['scid'=>self::scid($input->entry)],
            'entry-hash'=>['hash'=>self::entryHash($input->entry,$input->previousVersionId)],
            'sign'=>['proof'=>self::sign($input->document,$input->seed,$input)],
            'verify'=>['valid'=>self::verify($input->document,$input->proof)],
            'witness'=>['proof'=>self::sign((object)['versionId'=>$input->versionId],$input->seed,$input)],
            'create'=>self::create($input), 'update'=>self::update($input), 'resolve'=>self::resolve($input),
            default=>throw new \InvalidArgumentException('unknown operation '.$op)
        };
    }
}
