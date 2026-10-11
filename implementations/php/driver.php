<?php
declare(strict_types=1);
require __DIR__.'/src/VHLog.php';
ini_set('serialize_precision','-1');
while (($line=fgets(STDIN))!==false) {
    $request=null;
    try {
        $request=\VHLog\Log::parse($line);
        $response=['id'=>$request->id,'ok'=>true,'result'=>\VHLog\Log::dispatch($request->op,$request->input)];
    } catch (Throwable $e) { $response=['id'=>$request->id ?? null,'ok'=>false,'error'=>$e->getMessage()]; }
    fwrite(STDOUT,json_encode($response,JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)."\n");
    fflush(STDOUT);
}
