@load base/frameworks/notice
@load base/frameworks/sumstats

export {
    redef enum Notice::Type += {
        Metasploit::Meterpreter,
    };
}

# ref: https://www.bro.org/sphinx/scripts/base/bif/plugins/Bro_TCP.events.bif.bro.html#id-tcp_packet
event tcp_packet(c: connection, is_orig: bool, flags: string,
                 seq: count, ack: count, len: count, payload: string)
{
    SumStats::observe("TcpPktLengthStats", 
            SumStats::Key($str=fmt("%d", len), $host=c$id$orig_h), # ref: https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-connection
            SumStats::Observation($num=1));
    if (strstr(payload, "core_patch_url") > 0)
        {
            # Make an observation!
            # This observation is global so the key is empty.
            # Each established connection counts as one so the observation is always 1.
            # ref: https://www.bro.org/sphinx/scripts/base/frameworks/sumstats/main.bro.html#id-SumStats::observe
            SumStats::observe("Meterpreter.Beacon.Counter", 
                    SumStats::Key($str=fmt("%s", c$id$orig_h), $host=c$id$orig_h), # ref: https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-connection
                    SumStats::Observation($num=1));
            NOTICE([$note=Metasploit::Meterpreter, $conn=c, $msg=fmt("Possible Meterpreter Payload transfered!")]);
        }
}

event bro_init()
{
# Create the reducer.
# The reducer attaches to the "conn established" observation stream
# and uses the summing calculation on the observations.
    local r1 = SumStats::Reducer($stream="Meterpreter.Beacon.Counter", 
            $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="TcpPktLengthStats", 
            $apply=set(SumStats::SUM));

# Create the final sumstat.
# We give it an arbitrary name and make it collect data every minute.
# The reducer is then attached and a $epoch_result callback is given 
# to finally do something with the data collected.
    SumStats::create([$name = "Meterpreter Beacon Collector",
            $epoch = 1min,
            $reducers = set(r1),
            $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
# This is the body of the callback that is called when a single 
# result has been collected.  We are just printing the total number
# of connections that were seen.  The $sum field is provided as a 
# double type value so we need to use %f as the format specifier.
            print fmt("Number of beacon detected: %.0f of key: %s", result["Meterpreter.Beacon.Counter"]$sum, SumStats::key2str(key));
            }]);
    SumStats::create([$name = "TCP Stats",
            $epoch = 1min,
            $reducers = set(r2),
            $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
            {
            print fmt("stats_at %D , begin_at %D , end_at %D , orig_h is %s , pkt_len = %s occured %d times", ts, result["TcpPktLengthStats"]$begin, result["TcpPktLengthStats"]$end, key$host, key$str, result["TcpPktLengthStats"]$num);
            }]);
}

