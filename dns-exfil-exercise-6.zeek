@load base/frameworks/notice

export {
const private_address_space: set[subnet] = {
     10.0.0.0/8,
     192.168.0.0/16,
     172.16.0.0/12,
     100.64.0.0/10,  # RFC6598 Carrier Grade NAT
     127.0.0.0/8,
     [fe80::]/10,
     [::1]/128,
   } &redef;
}

export {
    redef enum Notice::Type += {
        #DNS::NXDomain,
        DNS::Tunneling,
        DNS::Oversized_Answer,
        DNS::Oversized_Query,
        DNS::Not_p53,
        DynDNS_CheckIp_External,
    };
    # DNS names to not alert on
    const ignore_DNS_names = /wpad|isatap|autodiscover|gstatic\.com$|domains\._msdcs|mcafee\.com$/ &redef;
    # size at which dns query domain name is considered interesting
    #to get this script to test fire properly with the pcap lower dns_query_oversize to 10.
    #also disable the check for private ip's in the if statement below that triggers it.
    const dns_query_oversize = 90 &redef;
    # query types to not alert on
    const ignore_qtypes = [12,32] &redef;
    # total DNS payload size over which to alert on
    const dns_plsize_alert = 576 &redef;  # increased size to match rfc
    # ports to ignore_DNS_names
    const dns_ports_ignore: set[port] = {137/udp, 137/tcp, 5353/udp, 5355/udp} &redef;
#added dyndns.org

const dyndns_host =
          /dyn\.com$/
          |/dyndns\.com$/
          |/dyndns\.net$/
          |/dyndns\.org$/
          |/dynu/
          |/no-ip\.com$/
          |/duckdns\.org$/
          |/afraid\.org$/
&redef;

event zeek_init()
    {
    local r3 = SumStats::Reducer($stream="Detect.dnsTunneling", $apply=set(SumStats::SUM));
    SumStats::create([$name="Detect.dnsTunneling",
            $epoch=5min,
            $reducers=set(r3),
            $threshold = 5.0,
            $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                {
                return result["Detect.dnsTunneling"]$sum;
                },
            $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                local dnsparts = split_string(key$str, /,/);
                NOTICE([$note=DNS::Tunneling,
                    $id=[$orig_h=key$host,$orig_p=to_port(dnsparts[0]),
                        $resp_h=to_addr(dnsparts[1]),$resp_p=to_port(dnsparts[2])],
                    $uid=dnsparts[5],
                    $msg=fmt("%s", dnsparts[3]),
                    $sub=fmt("%s", dnsparts[4]),
                    $identifier=cat(key$host,dnsparts[2]),
                    $sub=fmt("Severity: 9"),
                    $suppress_for=5min]);
                    }]); #check here for bug
    }


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if (qtype !in ignore_qtypes && c$id$resp_p !in dns_ports_ignore)
        {
        if (c$id$resp_p != 53/udp && c$id$resp_p != 53/tcp)
            {
            NOTICE([$note=DNS::Not_p53,
                $conn=c,
                $msg=fmt("%s is querying %s on a port that is not 53/udp: %s", c$id$orig_h, c$id$resp_h, query),
                $sub=fmt("Query type: %s", qtype),
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $sub=fmt("Severity: 1"),
                $suppress_for=40min]);
            }

        if (|query| > dns_query_oversize && ignore_DNS_names !in query)
            {
            NOTICE([$note=DNS::Oversized_Query,
                $conn=c,
                $msg=fmt("%s has issued an oversized query %s: %s", c$id$orig_h, c$id$resp_h, query),
                $sub=fmt("Query type: %s", qtype),
                $identifier=cat(c$id$orig_h,c$id$resp_h),
                $sub=fmt("Severity: 5"),
                $suppress_for=40min]);

            SumStats::observe("Detect.dnsTunneling",
                [$host=c$id$orig_h,
                $str=cat(c$id$orig_p,",",
                    c$id$resp_h,",",
                    c$id$resp_p,",",
                    cat("Query: ",query),",",
                    cat("Query type: ",qtype),",",
                    c$uid)],
                [$num=1]);
            }
        }
    }

event dns_query_reply(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
                {

        if ( dyndns_host in query )
                          {
                          NOTICE([$note=DynDNS_CheckIp_External,
                          $conn=c,
                          $msg=fmt("%s just received a Dynamic DNS IP Address Server Query Response - %s.", c$id$orig_h, query),
                          $identifier=cat(c$id$orig_h),
                          $sub=fmt("Severity: 1"),
                          $suppress_for=1hr]);
                          }
                }



event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count)
    {


    if (c$id$resp_h in private_address_space)
    {
        return;
    }

    if (len > dns_plsize_alert && c$id$orig_p !in dns_ports_ignore && c$id$resp_p !in dns_ports_ignore)
        {
        NOTICE([$note=DNS::Oversized_Answer,
            $conn=c,
            $msg=fmt("%s has issued an oversized answer to %s", c$id$orig_h, c$id$resp_h),
            $sub=fmt("Payload length: %sB", len),
            $identifier=cat(c$id$orig_h,c$id$resp_h),
            $sub=fmt("Severity: 5"),
            $suppress_for=60min]);

        SumStats::observe("Detect.dnsTunneling",
            [$host=c$id$orig_h,
            $str=cat(
                c$id$orig_p,",",
                c$id$resp_h,",",
                c$id$resp_p,",",
                cat("Payload length: ",len),",",
                " ",",",
                c$uid)],
            [$num=1]);
        }
    }
}
