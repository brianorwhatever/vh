require_relative 'lib/vh_log'
$stdout.sync = true
$stdin.each_line("\n") do |line|
  request = nil
  begin
    request = VHLog.parse(line)
    response = {'id'=>request['id'],'ok'=>true,'result'=>VHLog.dispatch(request['op'],request['input'])}
  rescue StandardError => e
    response = {'id'=>request && request['id'],'ok'=>false,'error'=>e.message}
  end
  puts JSON.generate(response)
end
