##! IPMI Protocol Analyzer

module IPMI;

export {
	redef enum Log::ID += { LOG };

  type Info: record {
    ## Timestamp for when the event happened.
    ts:               time &log;
    ## Unique ID for the connection.
    uid:              string  &log;
    ## The connection's 4-tuple of endpoint addresses/ports.
    id:               conn_id &log &optional;
    ## IPMI Behaviors
  };

	## Event that can be handled to access the IPMI record as it is sent on
	## to the logging framework.
	global log_ipmi: event(rec: Info);
}

const ports = { 623/tcp, 623/udp};
redef likely_server_ports += { ports };

redef record connection += {
	ipmi: Info &optional;
};

event zeek_init() &priority=5
{
  Log::create_stream(IPMI::LOG, [$columns=IPMI::Info, $ev=log_ipmi]);
}

function set_session(c: connection)
{
  if ( ! c?$ipmi) {
    add c$service["ipmi"];
    local info: IPMI::Info;
    info$ts = network_time();
    info$id = c$id;
    info$uid = c$uid;
    c$ipmi = info;
  }
}

## Event Data for ipmi

event new_connection(c: connection) &priority=5
{
	set_session(c);
}

event new_connection(c: connection) &priority=5
{
  if ( c?$ipmi && c$id$resp_p in ports ) {
    Log::write(IPMI::LOG, c$ipmi);
    delete c$ipmi;
  }
}
