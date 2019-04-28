# @TEST-PORT: BROKER_PORT
# @TEST-EXEC: unset BRO_DISABLE_BROXYGEN; bro -b -X zeexygen.config %INPUT Broker::default_port=$BROKER_PORT
# @TEST-EXEC: btest-diff test.rst

@TEST-START-FILE zeexygen.config
identifier	ZeexygenExample::*	test.rst
@TEST-END-FILE

@load zeexygen
