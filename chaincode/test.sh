#!/bin/bash

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
FPC_TOP_DIR="${SCRIPTDIR}/../.."
FABRIC_CFG_PATH="${SCRIPTDIR}/../../integration/config"
FABRIC_SCRIPTDIR="${FPC_TOP_DIR}/fabric/bin/"

. ${FABRIC_SCRIPTDIR}/lib/common_utils.sh
. ${FABRIC_SCRIPTDIR}/lib/common_ledger.sh

CC_ID=GPM_test

#this is the path that will be used for the docker build of the chaincode enclave
ENCLAVE_SO_PATH=examples/chaincode/_build/lib/

CC_VERS=0

GPM_test() {
    say "- do hello world"
    # install and instantiate GPM  chaincode

    # builds the docker image; creates the docker container and enclave;
    # input:  CC_ID:chaincode name; CC_VERS:chaincode version;
    #         ENCLAVE_SO_PATH:path to build artifacts

    say "- install GPM chaincode"
    try ${PEER_CMD} chaincode install -l fpc-c -n ${CC_ID} -v ${CC_VERS} -p ${ENCLAVE_SO_PATH}
    sleep 3

    # instantiate GPM chaincode
    say "- instantiate GPM chaincode"
    try ${PEER_CMD} chaincode instantiate -o ${ORDERER_ADDR} -C ${CHAN_ID} -n ${CC_ID} -v ${CC_VERS} -c '{"args":["init"]}' -V ecc-vscc
    sleep 3

    for i in {1..1}
    do
        say "- Register PDID"
        try ${PEER_CMD} chaincode invoke -o ${ORDERER_ADDR} -C ${CHAN_ID} -n ${CC_ID} -c ${REQ_newPDID} --waitForEvent
    done

    for i in {1..1}
    do
        say " - Auth via PDID"
        try ${PEER_CMD} chaincode invoke -o ${ORDERER_ADDR} -C ${CHAN_ID} -n ${CC_ID} -c ${REQ_authPDID} --waitForEvent
    done

}

# 1. prepare
para
say "Preparing GPM Test ..."
# - clean up relevant docker images
docker_clean ${ERCC_ID}
docker_clean ${CC_ID}

trap ledger_shutdown EXIT

para
say "Run GPM  test"

say "- setup ledger"
ledger_init

say "- GPM test"
GPM_test

say "- shutdown ledger"
ledger_shutdown

para
yell "GPM test PASSED"

exit 0
