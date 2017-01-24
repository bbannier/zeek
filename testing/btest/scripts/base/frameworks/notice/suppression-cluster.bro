# @TEST-SERIALIZE: comm
#
# @TEST-EXEC: btest-bg-run manager-1 BROPATH=$BROPATH:.. CLUSTER_NODE=manager-1 bro %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: btest-bg-run data-1   BROPATH=$BROPATH:.. CLUSTER_NODE=data-1 bro %INPUT
# @TEST-EXEC: sleep 2
# @TEST-EXEC: btest-bg-run worker-1  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-1 bro %INPUT
# @TEST-EXEC: btest-bg-run worker-2  BROPATH=$BROPATH:.. CLUSTER_NODE=worker-2 bro %INPUT
# @TEST-EXEC: btest-bg-wait 20
# @TEST-EXEC: btest-diff manager-1/notice.log

@TEST-START-FILE cluster-layout.bro
redef Cluster::nodes = {
	["manager-1"] = [$node_roles=set(Cluster::MANAGER, Cluster::LOGGER), $ip=127.0.0.1, $p=27757/tcp, $workers=set("worker-1", "worker-2")],
	["data-1"] = [$node_roles=set(Cluster::DATANODE),  $ip=127.0.0.1, $p=27758/tcp, $manager="manager-1", $workers=set("worker-1", "worker-2")],
	["worker-1"] = [$node_roles=set(Cluster::WORKER),  $ip=127.0.0.1, $p=27760/tcp, $manager="manager-1", $datanodes=set("data-1")],
	["worker-2"] = [$node_roles=set(Cluster::WORKER),  $ip=127.0.0.1, $p=27761/tcp, $manager="manager-1", $datanodes=set("data-1")],
};
@TEST-END-FILE

redef Log::default_rotation_interval = 0secs;

redef enum Notice::Type += {
	Test_Notice,
};

event Broker::incoming_connection_broken(peer_name: string)
	{
	terminate();
	}

event Broker::outgoing_connection_broken(peer_address: string,
                                        peer_port: port, peer_name: string)
	{
	terminate();
	}

global ready: event();

redef Cluster::manager2worker_events += {"ready"};

event delayed_notice()
	{
	NOTICE([$note=Test_Notice,
	        $msg="test notice!",
	        $identifier="this identifier is static"]);
	}

@if ( Cluster::has_local_role(Cluster::WORKER) )

event ready()
    {
	if ( Cluster::node == "worker-1" )
		schedule 4secs { delayed_notice() };
	if ( Cluster::node == "worker-2" )
		schedule 1secs { delayed_notice() };
    }

event Notice::suppressed(n: Notice::Info)
	{
	if ( Cluster::node == "worker-1" )
		terminate();
	}

@endif

@if ( Cluster::has_local_role(Cluster::MANAGER) )

global peer_count = 0;

event Broker::incoming_connection_established(peer_name: string)
	{
	peer_count += 1;
	if ( peer_count == 3 )
		event ready();
	}

@endif
