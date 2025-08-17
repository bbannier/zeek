# @TEST-DOC: Test protobuf serializer
#
# @TEST-EXEC: zeek %INPUT >>out 2>&1
# @TEST-EXEC: btest-diff out

module Protobuf;

type Enum: enum {
	E_A,
};

type Record: record {
	a: count;
	b: string;
};

event zeek_init()
	{
	assert T == deserialize(serialize(T), bool) as bool;
	assert 42 == deserialize(serialize(42), count) as count;
	assert +42 == deserialize(serialize(+42), int) as int;
	assert 1.5 == deserialize(serialize(1.5), double) as double;
	assert 42secs == deserialize(serialize(42secs), interval) as interval;
	assert double_to_time(42) == deserialize(serialize(double_to_time(42)), time) as time;
	assert /abc/ == deserialize(serialize(/abc/), pattern) as pattern;

	assert E_A == deserialize(serialize(E_A), Enum) as Enum;

	assert 127.0.0.1 == deserialize(serialize(127.0.0.1), addr) as addr;
	assert [2001:db8:3333:4444:5555:6666:1.2.3.4]	== deserialize(serialize([2001:db8:3333:4444:5555:6666:1.2.3.4]), addr) as addr;

	assert 192.0.0.0/8 == deserialize(serialize(192.0.0.0/8), subnet) as subnet;

	assert 8080/tcp == deserialize(serialize(8080/tcp), port) as port;
	assert 8080/udp == deserialize(serialize(8080/udp), port) as port;
	assert 123/icmp == deserialize(serialize(123/icmp), port) as port;
	assert 0/unknown == deserialize(serialize(0/unknown), port) as port;

	local vec_given = vector(1, 2, 3);
	local vec_actual = deserialize(serialize(vec_given), vector of count) as vector of count;
	assert |vec_given| == |vec_actual|;
	for (i in vec_given)
		assert vec_given[i] == vec_actual[i];

	local tab_given = {
		[1] = "1",
		[2] = "2"
	};
	local tab_actual = deserialize(serialize(tab_given), table[count] of string) as table[count] of string;
	assert |tab_given| == |tab_actual|;
	for (i in tab_given)
		assert tab_given[i] == tab_actual[i];

	assert set(1, 2, 3) == deserialize(serialize(set(1, 2, 3)), set[count]) as set[count];

	local rec_given = Record($a=1, $b="abc");
	local rec_actual = deserialize(serialize(rec_given), Record) as Record;
	assert rec_given$a == rec_actual$a;
	assert rec_given$b == rec_actual$b;
	}

