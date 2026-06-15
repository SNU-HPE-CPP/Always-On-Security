@load base/protocols/conn
@load base/protocols/ssh
@load base/frameworks/notice

module HPCMon;

export {
    redef enum Notice::Type += {
        Unauthorized_Comm,
        Lateral_Movement,
        Fanout_Excess,
        Baseline_Deviation,
        Protocol_Mismatch,
    };

    const warmup_window = 30min &redef;
    const fanout_threshold = 3 &redef;
    const hop_chain_threshold = 2 &redef;

    global service_allowlist: table[addr] of set[port] = table();
    global expected_pairs: table[string] of bool = table();
    global peer_sets: table[addr] of set[addr] = table();
    global ssh_hops: table[string] of count = table();
    global pair_last_seen: table[string] of time = table();
    global pair_counts: table[addr] of count = table();
    global baseline_pairs: table[addr] of count = table();
    global warmup_started: time = network_time();
}

function pair_key(src: addr, dst: addr): string
    {
    return fmt("%s->%s", src, dst);
    }

function allowed_port(src: addr, p: port): bool
    {
    return src in service_allowlist && p in service_allowlist[src];
    }

function expected_pair(src: addr, dst: addr): bool
    {
    local key = pair_key(src, dst);
    return key in expected_pairs;
    }

function record_peer(src: addr, dst: addr)
    {
    if ( src !in peer_sets )
        peer_sets[src] = set();
    add peer_sets[src][dst];

    if ( src in pair_counts )
        pair_counts[src] += 1;
    else
        pair_counts[src] = 1;
    }

function fanout_notice(src: addr)
    {
    if ( src in peer_sets && |peer_sets[src]| > fanout_threshold )
        NOTICE([$note=Fanout_Excess, $msg=fmt("Fan-out threshold exceeded by %s: %d peers", src, |peer_sets[src]|), $src=src]);
    }

function hop_notice(src: addr, dst: addr)
    {
    local key = pair_key(src, dst);
    if ( key in ssh_hops && ssh_hops[key] >= hop_chain_threshold )
        NOTICE([$note=Lateral_Movement, $msg=fmt("SSH hop chain detected %s with hop count %d", key, ssh_hops[key]), $src=src, $dst=dst]);
    }

function baseline_collect(src: addr)
    {
    if ( src in baseline_pairs )
        baseline_pairs[src] += 1;
    else
        baseline_pairs[src] = 1;
    }

event zeek_init()
    {
    service_allowlist[10.10.1.21] = set(22/tcp, 50000/tcp, 50001/tcp, 50002/tcp);
    service_allowlist[10.10.1.22] = set(22/tcp, 50000/tcp, 50001/tcp, 50002/tcp);
    service_allowlist[10.10.1.23] = set(22/tcp, 50000/tcp, 50001/tcp, 50002/tcp);
    service_allowlist[10.10.2.31] = set(22/tcp, 2049/tcp);
    service_allowlist[10.10.3.10] = set(22/tcp, 5514/tcp, 5555/tcp, 5556/tcp);
    service_allowlist[10.10.3.11] = set(22/tcp, 5514/tcp, 5555/tcp, 5556/tcp);
    service_allowlist[10.10.3.12] = set(22/tcp, 5514/tcp, 5555/tcp, 5556/tcp);
    service_allowlist[10.10.3.31] = set(22/tcp, 5514/tcp, 5555/tcp, 5556/tcp);

    expected_pairs[pair_key(10.10.1.21, 10.10.1.22)] = T;
    expected_pairs[pair_key(10.10.1.22, 10.10.1.23)] = T;
    expected_pairs[pair_key(10.10.1.23, 10.10.2.31)] = T;
    expected_pairs[pair_key(10.10.3.10, 10.10.3.11)] = T;
    expected_pairs[pair_key(10.10.3.11, 10.10.3.12)] = T;
    }

event conn_state_remove(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local p = c$id$resp_p;
    local key = pair_key(src, dst);

    if ( ! expected_pair(src, dst) )
        NOTICE([$note=Unauthorized_Comm, $msg=fmt("Unexpected connection pair %s -> %s", src, dst), $src=src, $dst=dst]);

    if ( src in service_allowlist && ! allowed_port(src, p) )
        NOTICE([$note=Protocol_Mismatch, $msg=fmt("Container %s accessed disallowed port %s on %s", src, p, dst), $src=src, $dst=dst]);

    record_peer(src, dst);
    fanout_notice(src);

    if ( c$service == "ssh" )
        {
        if ( key in ssh_hops )
            ssh_hops[key] += 1;
        else
            ssh_hops[key] = 1;
        hop_notice(src, dst);
        }

    if ( network_time() - warmup_started < warmup_window )
        baseline_collect(src);
    else if ( src in baseline_pairs && pair_counts[src] > baseline_pairs[src] * 3 )
        {
        NOTICE([$note=Baseline_Deviation, $msg=fmt("Connection-rate deviation for %s: observed=%d baseline=%d", src, pair_counts[src], baseline_pairs[src]), $src=src, $dst=dst]);
        }
    }
