using System.Text;
using System.Text.Json.Nodes;
using VHLog;

Console.InputEncoding = Encoding.UTF8;
Console.OutputEncoding = new UTF8Encoding(false);
var line = new StringBuilder();
void Handle(string text)
{
    JsonNode? id = null; JsonNode response;
    try
    {
        var request = Log.Parse(text)!; id = request["id"];
        response = Log.Obj("id", id, "ok", true, "result", Log.Dispatch(request["op"]!.GetValue<string>(), request["input"]!));
    }
    catch (Exception e) { response = Log.Obj("id", id, "ok", false, "error", e.Message); }
    Console.WriteLine(Log.Canonicalize(response));
}
int c;
while ((c = Console.Read()) != -1)
{
    if (c == '\n') { Handle(line.ToString()); line.Clear(); }
    else line.Append((char)c);
}
if (line.Length > 0) Handle(line.ToString());
