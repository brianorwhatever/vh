package vhlog
import ujson.*
object Driver {
  def main(args: Array[String]): Unit = {
    val reader=new java.io.BufferedReader(new java.io.InputStreamReader(System.in,java.nio.charset.StandardCharsets.UTF_8))
    var line=reader.readLine()
    while(line!=null) {
      var id: Value=Null
      val response=try {
        val request=VHLog.parse(line); id=request.obj.getOrElse("id",Null)
        Obj("id"->id,"ok"->true,"result"->VHLog.dispatch(request("op").str,request("input")))
      } catch { case e: Exception => Obj("id"->id,"ok"->false,"error"->Option(e.getMessage).getOrElse(e.getClass.getName)) }
      println(VHLog.jcs(response))
      line=reader.readLine()
    }
  }
}
