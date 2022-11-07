#!/bin/bash
set -e

###################################
SUDO="sudo -u"
# Environment variables
WORK_DIR=${WORKDIR:-$HOME}
BINARIES_DIR={BINARIES_DIR:-$WORK_DIR/isecl-build/binaries}
ISECL_RELEASE=${ISECL_RELEASE:-v4.2.0-Beta}
SCS_RELEASE=${SCS_RELEASE-v4.1.2}
SQVS_RELEASE=${SQVS_RELEASE:-v4.1.2}
UTILS_RELEASE=${UTILS_RELEASE:-v4.2/develop}

SYSTEM_IP=${SYSTEM_IP:-$(ip -o route get to 1 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')}
SYSTEM_SAN=${SYSTEM_SAN:-"localhost,$(hostname),${SYSTEM_IP}"}

INSTALL_ADMIN_USERNAME=${INSTALL_ADMIN_USERNAME:-"admin"}
INSTALL_ADMIN_PASSWORD=${INSTALL_ADMIN_PASSWORD:-"admin"}

AAS_PORT=${AAS_PORT:-8444}
AAS_URL=https://$SYSTEM_IP:$AAS_PORT/aas/v1
AAS_ADMIN_USERNAME=${AAS_ADMIN_USERNAME:-"admin@aas"}
AAS_ADMIN_PASSWORD=${AAS_ADMIN_PASSWORD:-"admin"}
AAS_DB_NAME=${AAS_DB_NAME:-"aasdb"}
AAS_DB_USERNAME=${AAS_ADMIN_USERNAME:-"user@aasdb"}
AAS_DB_PASSWORD=${AAS_DB_PASSWORD:-"aasdbpwd"}

CMS_PORT=${CMS_PORT:-8445}
CMS_URL=https://$SYSTEM_IP:$CMS_PORT/cms/v1/

KBS_PORT=9443
KBS_SERVICE_USERNAME=${KBS_SERVICE_USERNAME:-"user@kub"}
KBS_SERVICE_PASSWORD=${KBS_SERVICE_PASSWORD:-"kbspasswd"}

SCS_PORT=${SCS_PORT:-9000}
SCS_URL=https://$SYSTEM_IP:$SCS_PORT/scs/sgx/certification/v1
SCS_ADMIN_USERNAME=${SCS_ADMIN_USERNAME:-"admin@scs"}
SCS_ADMIN_PASSWORD=${SCS_ADMIN_PASSWORD:-"admin"}
SCS_DB_NAME=${SCS_DB_NAME:-"scsdb"}
SCS_DB_USERNAME=${SCS_ADMIN_USERNAME:-"user@scsdb"}
SCS_DB_PASSWORD=${SCS_DB_PASSWORD:-"scsdbpwd"}

INTEL_PROVISIONING_SERVER="https://api.trustedservices.intel.com/sgx/certification/v3"
API_KEY=${API_KEY}

SQVS_URL=https://$SYSTEM_IP:$SQVS_PORT/svs/v1

KMIP_SERVER_PORT=${KMIP_SERVER_PORT=5696}
KMIP_CLIENT_CERT_PATH=${KMIP_CLIENT_CERT_PATH:-"/etc/pykmip/client_certificate.pem"}
KMIP_CLIENT_KEY_PATH=${KMIP_CLIENT_KEY_PATH:-"/etc/pykmip/client_key.pem"}
KMIP_ROOT_CERT_PATH=${KMIP_ROOT_CERT_PATH=:-"/etc/pykmip/root_certififcate.pem"}

TAC_CN=trusted-attestation-controller # CommonName used for TAC client certificate
TAC_USERNAME=tacuser
TAC_PASSWORD=tacpasswd
###############################################################################

CMS_TLS_SHA=
ADMIN_TOKEN=
CMS_TLS_SHA=

clone_repos()
{
    ## clone repos
    if [ ! -d intel-secl ]; then
        git clone --depth=1 --branch $ISECL_RELEASE https://github.com/intel-secl/intel-secl.git
    else
        (cd intel-secl && git checkout $ISECL_RELEASE)
    fi
    if [ ! -d sgx-caching-service ]; then
        git clone --depth=1 --branch $SCS_RELEASE https://github.com/intel-secl/sgx-caching-service.git
    else
        (cd sgx-caching-service && git checkout $SCS_RELEASE)
    fi
    if [ ! -d sgx-verification-service ]; then
        git clone --depth=1 --branch $SQVS_RELEASE  https://github.com/intel-secl/sgx-verification-service.git
    else
        (cd sgx-verification-service && git checkout $SQVS_RELEASE)
    fi
    set -x
    if [ ! -d utils ]; then
        git clone --depth=1 --branch $UTILS_RELEASE https://github.com/intel-secl/utils.git
    else
        (cd utils && git checkout $UTILS_RELEASE)
    fi
}

## build installer binaries
build_binaries()
{
    (cd intel-secl && make cms-installer authservice-installer kbs-installer aas-manager)
    (cd sgx-caching-service && make installer)
    (cd sgx-verification-service && make installer)
}

## copy all binaries and  environment files to $BINARIES_DIR
copy_binaries()
{
    mkdir -p $BINARIES_DIR/env &&
    cp intel-secl/deployments/installer/*.bin $BINARIES_DIR/ &&
    cp intel-secl/deployments/installer/create_db.sh $BINARIES_DIR/ &&
    cp intel-secl/deployments/installer/populate-users.sh $BINARIES_DIR/ &&
    cp intel-secl/tools/aas-manager/populate-users.env $BINARIES_DIR/env &&
    cp sgx-caching-service/out/*.bin $BINARIES_DIR/ &&
    cp sgx-caching-service/dist/linux/scs.env $BINARIES_DIR/env &&
    cp sgx-verification-service/out/*.bin $BINARIES_DIR/ &&
    cp sgx-verification-service/dist/linux/sqvs.env $BINARIES_DIR/env &&
    cp sgx-verification-service/dist/linux/trusted_rootca_icx_prod.pem $BINARIES_DIR/trusted_rootca.pem &&
    cp -pf utils/build/skc-tools/skc_scripts/env/{authservice,cms,iseclpgdb,kbs}.env $BINARIES_DIR/env &&
    cp -pf utils/build/skc-tools/skc_scripts/env/install_pgdb.sh $BINARIES_DIR/ &&
    cp -pf utils/build/skc-tools/skc_scripts/install_sgx_infra.sh $BINARIES_DIR/ &&
    cp -pf utils/build/skc-tools/kbs_script/*.sh $BINARIES_DIR/ &&
    cp -pf utils/build/skc-tools/kbs_script/server.conf $BINARIES_DIR/
}

uninstall_all()
{
    echo "Uninstalling Certificate Management Service...."
    $SUDO /opt/cms/bin/cms uninstall --purge
    echo "Uninstalling AuthService...."
    $SUDO /opt/authservice/bin/authservice uninstall --purge
    echo "Removing AuthService Database...."
    $SUDO postgres dropdb $AAS_DB_NAME
    echo "Uninstalling SGX Caching Service...."
    $SUDO /opt/scs/bin/scs uninstall --purge
    echo "Removing SGX Caching Service Database...."
    $SUDO postgres dropdb $SCS_DB_NAME
    echo "Uninstalling SGX Quote Verification Service...."
    $SUDO /opt/sqvs/bin/sqvs uninstall --purge
    echo "Uninstalling Key Broker Service...."
    $SUDO /opt/kbs/bin/kbs uninstall --purge
}

install_pgdb()
{
    echo "Installing Postgres....."
    $SUDO $BINARIES_DIR/install_pgdb.sh
    if [ $? -ne 0 ]; then
        echo "Postgres installation failed!!"
        exit 1
    fi
    echo "Postgres installated successfully."
}

install_databases()
{
    echo "Creating AAS database....."
    $SUDO $BINARIES_DIR/create_db.sh $AAS_DB_NAME $AAS_DB_USERNAME $AAS_DB_PASSWORD
    if [ $? -ne 0 ]; then
        echo "Authservice db creation failed!!"
        exit 1
    fi
    echo "AAS database created successfully."

    echo "Creating SCS database....."
    $SUDO $BINARIES_DIR/create_db.sh $SCS_DB_NAME $SCS_DB_USERNAME $SCS_DB_PASSWORD
    if [ $? -ne 0 ]; then
        echo "SCS db creation failed!!"
        exit 1
    fi
    echo "SCS database created successfully."
}

install_cms()
{
    echo "Installing Certificate Management Service...."
    sed -i "s/^\(AAS_TLS_SAN\s*=\s*\).*\$/\1$SYSTEM_SAN/" ~/cms.env
    sed -i "s@^\(AAS_API_URL\s*=\s*\).*\$@\1$AAS_URL@" ~/cms.env
    sed -i "s/^\(SAN_LIST\s*=\s*\).*\$/\1$SYSTEM_SAN/" ~/cms.env

    (cd $BINARIES_DIR; $SUDO cms-*.bin)
    $SUDO /opt/cms/bin/cms status > /dev/null
    if [ $? -ne 0 ]; then
	    echo "Certificate Management Service Installation Failed!!"
	    exit 1
    fi
    echo "Installed Certificate Management Service."
    CMS_TLS_SHA=$($SUDO /opt/cms/bin/cms tlscertsha384)
}

install_authservice()
{
    cp $BINARIES_DIR/env/authservice.env ~/authservice.env
    trap rm -f ~/authservice.env EXIT
    echo "Copying Certificate Management Service token to AuthService...."
    export AAS_TLS_SAN=$SYSTEM_SAN
    CMS_TOKEN=$($SUDO /opt/cms/bin/cms setup cms-auth-token --force | grep 'JWT Token:' | awk '{print $3}')
    sed -i "s/^\(BEARER_TOKEN\s*=\s*\).*\$/\1$CMS_TOKEN/" ~/authservice.env

    sed -i "s/^\(CMS_TLS_CERT_SHA384\s*=\s*\).*\$/\1$CMS_TLS_SHA/" ~/authservice.env
    sed -i "s@^\(CMS_BASE_URL\s*=\s*\).*\$@\1$CMS_URL@" ~/authservice.env
    sed -i "s/^\(SAN_LIST\s*=\s*\).*\$/\1$SYSTEM_SAN/" ~/authservice.env
    sed -i "s/^\(AAS_ADMIN_USERNAME\s*=\s*\).*\$/\1$AAS_ADMIN_USERNAME/" ~/authservice.env
    sed -i "s/^\(AAS_ADMIN_PASSWORD\s*=\s*\).*\$/\1$AAS_ADMIN_PASSWORD/" ~/authservice.env
    sed -i "s/^\(AAS_DB_NAME\s*=\s*\).*\$/\1$AAS_DB_NAME/" ~/authservice.env
    sed -i "s/^\(AAS_DB_USERNAME\s*=\s*\).*\$/\1$AAS_DB_USERNAME/" ~/authservice.env
    sed -i "s/^\(AAS_DB_PASSWORD\s*=\s*\).*\$/\1$AAS_DB_PASSWORD/" ~/authservice.env

    echo "Installing AuthService...."
    $SUDO $BINARIES_DIR/authservice-*.bin
    $SUDO /opt/authservice/bin/authservice status > /dev/null
    if [ $? -ne 0 ]; then
	    echo "AuthService Installation Failed!!"
	    exit 1
    fi
    echo "Installed AuthService."
}

populate_users()
{
    cp $BINARIES_DIR/env/populate-users.env ~/populate-users.env
    trap rm -f ~/populate-users.env EXIT
    echo "Updating Populate users env ...."
    ISECL_INSTALL_COMPONENTS=AAS,SCS,SQVS,KBS,SKC-LIBRARY
    sed -i "s@^\(ISECL_INSTALL_COMPONENTS\s*=\s*\).*\$@\1$ISECL_INSTALL_COMPONENTS@" ~/populate-users.env
    sed -i "s@^\(AAS_API_URL\s*=\s*\).*\$@\1$AAS_URL@" ~/populate-users.env
    sed -i "s/^\(AAS_ADMIN_USERNAME\s*=\s*\).*\$/\1$AAS_ADMIN_USERNAME/" ~/populate-users.env
    sed -i "s/^\(AAS_ADMIN_PASSWORD\s*=\s*\).*\$/\1$AAS_ADMIN_PASSWORD/" ~/populate-users.env
    sed -i "s@^\(SCS_CERT_SAN_LIST\s*=\s*\).*\$@\1$SYSTEM_SAN@" ~/populate-users.env
    sed -i "s@^\(SQVS_CERT_SAN_LIST\s*=\s*\).*\$@\1$SYSTEM_SAN@" ~/populate-users.env
    sed -i "s/^\(SCS_SERVICE_USERNAME\s*=\s*\).*\$/\1$SCS_ADMIN_USERNAME/" ~/populate-users.env
    sed -i "s/^\(SCS_SERVICE_PASSWORD\s*=\s*\).*\$/\1$SCS_ADMIN_PASSWORD/" ~/populate-users.env
    sed -i "s/^\(INSTALL_ADMIN_USERNAME\s*=\s*\).*\$/\1$INSTALL_ADMIN_USERNAME/" ~/populate-users.env
    sed -i "s/^\(INSTALL_ADMIN_PASSWORD\s*=\s*\).*\$/\1$INSTALL_ADMIN_PASSWORD/" ~/populate-users.env
    sed -i "s/^\(SKC_LIBRARY_CERT_COMMON_NAME\s*=\s*\).*\$/\1$TAC_CN/" ~/populate-users.env
    sed -i "s/^\(SKC_LIBRARY_USERNAME\s*=\s*\).*\$/\1$TAC_USERNAME/" ~/populate-users.env
    sed -i "s/^\(SKC_LIBRARY_PASSWORD\s*=\s*\).*\$/\1$TAC_PASSWORD/" ~/populate-users.env
    sed -i "s/^\(KBS_CERT_SAN_LIST\s*=\s*\).*\$/\1$SYSTEM_SAN/" ~/populate-users.env
    sed -i "s/^\(KBS_SERVICE_USERNAME\s*=\s*\).*\$/\1$KBS_SERVICE_USERNAME/" ~/populate-users.env
    sed -i "s/^\(KBS_SERVICE_PASSWORD\s*=\s*\).*\$/\1$KBS_SERVICE_PASSWORD/" ~/populate-users.env

    sed -i "/GLOBAL_ADMIN_USERNAME/d" ~/populate-users.env
    sed -i "/GLOBAL_ADMIN_PASSWORD/d" ~/populate-users.env

    echo "Invoking populate users script...."
    (cd $BINARIES_DIR; populate-users.sh
    if [ $? -ne 0 ]; then
	    echo "Populate user script failed!!"
	    exit 1
    fi)
}

install_scs()
{
    echo "Getting AuthService Admin token...."
    ADMIN_TOKEN=$(curl --noproxy "*" -k -X POST $AAS_URL/token -d '{"username": "'"$INSTALL_ADMIN_USERNAME"'", "password": "'"$INSTALL_ADMIN_PASSWORD"'"}')
    if [ $? -ne 0 ]; then
	    echo "Failed to fetch admin token!!"
	    exit 1
    fi
    if [ -z "$API_KEY" ]; then
        echo "No API_KEY set. Set the sgx provisioner API subscription via API_KEY environment variable"
        exit 1
    fi

    cp $BINARIES_DIR/env/scs.env ~/scs.env
    trap rm -f ~/scs.env EXIT
    SCS_DB_HOSTNAME="localhost"
    SCS_DB_SSLCERTSRC="/usr/local/pgsql/data/server.crt"
    sed -i "s/^\(SAN_LIST\s*=\s*\).*\$/\1$SYSTEM_SAN/" ~/scs.env
    sed -i "s/^\(SCS_ADMIN_USERNAME\s*=\s*\).*\$/\1$SCS_ADMIN_USERNAME/" ~/scs.env
    sed -i "s/^\(SCS_ADMIN_PASSWORD\s*=\s*\).*\$/\1$SCS_ADMIN_PASSWORD/" ~/scs.env
    sed -i "s/^\(BEARER_TOKEN\s*=\s*\).*\$/\1$ADMIN_TOKEN/" ~/scs.env
    sed -i "s/^\(CMS_TLS_CERT_SHA384\s*=\s*\).*\$/\1$CMS_TLS_SHA/" ~/scs.env
    sed -i "s@^\(AAS_API_URL\s*=\s*\).*\$@\1$AAS_URL@" ~/scs.env
    sed -i "s@^\(CMS_BASE_URL\s*=\s*\).*\$@\1$CMS_URL@" ~/scs.env
    sed -i "s@^\(INTEL_PROVISIONING_SERVER\s*=\s*\).*\$@\1$INTEL_PROVISIONING_SERVER@" ~/scs.env
    sed -i "s@^\(INTEL_PROVISIONING_SERVER_API_KEY\s*=\s*\).*\$@\1$API_KEY@" ~/scs.env
    sed -i "s/^\(SCS_DB_NAME\s*=\s*\).*\$/\1$SCS_DB_NAME/" ~/scs.env
    sed -i "s/^\(SCS_DB_USERNAME\s*=\s*\).*\$/\1$SCS_DB_USERNAME/" ~/scs.env
    sed -i "s/^\(SCS_DB_PASSWORD\s*=\s*\).*\$/\1$SCS_DB_PASSWORD/" ~/scs.env
    sed -i "s/^\(SCS_DB_HOSTNAME\s*=\s*\).*\$/\1$SCS_DB_HOSTNAME/" ~/scs.env
    sed -i "s@^\(SCS_DB_SSLCERTSRC\s*=\s*\).*\$@\1$SCS_DB_SSLCERTSRC@" ~/scs.env

    echo "Installing SGX Caching Service...."
    (cd $BINARIES_DIR; $SUDO ./scs-*.bin)
    $SUDO /opt/scs/bin/scs status > /dev/null
    if [ $? -ne 0 ]; then
	    echo "SGX Caching Service Installation Failed!!"
	    exit 1
    fi
    echo "Installed SGX Caching Service."
}

install_sqvs()
{
    ADMIN_TOKEN=$(curl --noproxy "*" -k -X POST $AAS_URL/token -d '{"username": "'"$INSTALL_ADMIN_USERNAME"'", "password": "'"$INSTALL_ADMIN_PASSWORD"'"}')
    if [ $? -ne 0 ]; then
	    echo "Failed to fetch admin token!!"
	    exit 1
    fi
    cp $BINARIES_DIR/env/sqvs.env ~/sqvs.env
    trap rm -f ~/sqvs.env EXIT

    echo "Updating SGX Quote Verification Service env...."
    sed -i "s/^\(SAN_LIST\s*=\s*\).*\$/\1$SYSTEM_SAN/" ~/sqvs.env
    sed -i "s/^\(BEARER_TOKEN\s*=\s*\).*\$/\1$ADMIN_TOKEN/" ~/sqvs.env
    sed -i "s/^\(CMS_TLS_CERT_SHA384\s*=\s*\).*\$/\1$CMS_TLS_SHA/" ~/sqvs.env
    sed -i "s@^\(AAS_API_URL\s*=\s*\).*\$@\1$AAS_URL@" ~/sqvs.env
    sed -i "s@^\(CMS_BASE_URL\s*=\s*\).*\$@\1$CMS_URL@" ~/sqvs.env
    sed -i "s@^\(SCS_BASE_URL\s*=\s*\).*\$@\1$SCS_URL@" ~/sqvs.env
    sed -i "s@^\(SGX_TRUSTED_ROOT_CA_PATH\s*=\s*\).*\$@\1$BINARIES_DIR/trusted_rootca.pem@" ~/sqvs.env
    echo "Installing SGX Quote Verification Service...."
    (cd $BINARIES_DIR; $SUDO ./sqvs-*.bin)
    $SUDO /opt/sqvs/bin/sqvs status > /dev/null
    if [ $? -ne 0 ]; then
    	echo "SGX Quote Verification Service Installation Failed!!"
    	exit 1
    fi
    echo "Installed SGX Quote Verification Service."
}

install_kbs()
{
    ADMIN_TOKEN=$(curl --noproxy "*" -k -X POST $AAS_URL/token -d '{"username": "'"$INSTALL_ADMIN_USERNAME"'", "password": "'"$INSTALL_ADMIN_PASSWORD"'"}')
    if [ $? -ne 0 ]; then
	    echo "Failed to fetch admin token!!"
	    exit 1
    fi
    KBS_HOSTNAME="$(hostname)"

    cp $BINARIES_DIR/env/kbs.env ~/kbs.env
    trap rm -f ~/kbs.env EXIT

    echo "Updating Key Broker Service env...."
    sed -i "s/^\(TLS_SAN_LIST\s*=\s*\).*\$/\1$SYSTEM_SAN,$KBS_HOSTNAME/" ~/kbs.env
    sed -i "s/^\(KBS_SERVICE_USERNAME\s*=\s*\).*\$/\1$KBS_SERVICE_USERNAME/" ~/kbs.env
    sed -i "s/^\(KBS_SERVICE_PASSWORD\s*=\s*\).*\$/\1$KBS_SERVICE_PASSWORD/" ~/kbs.env
    sed -i "s/^\(BEARER_TOKEN\s*=\s*\).*\$/\1$ADMIN_TOKEN/" ~/kbs.env
    sed -i "s/^\(CMS_TLS_CERT_SHA384\s*=\s*\).*\$/\1$CMS_TLS_SHA/" ~/kbs.env
    sed -i "s@^\(AAS_API_URL\s*=\s*\).*\$@\1$AAS_URL@" ~/kbs.env
    sed -i "s@^\(CMS_BASE_URL\s*=\s*\).*\$@\1$CMS_URL@" ~/kbs.env
    sed -i "s@^\(SQVS_URL\s*=\s*\).*\$@\1$SQVS_URL@" ~/kbs.env
    ENDPOINT_URL=https://$SYSTEM_IP:$KBS_PORT/kbs/v1
    sed -i "s@^\(ENDPOINT_URL\s*=\s*\).*\$@\1$ENDPOINT_URL@" ~/kbs.env

    sed -i "s@^\(KMIP_SERVER_IP\s*=\s*\).*\$@\1$SYSTEM_IP@" ~/kbs.env
    sed -i "s@^\(KMIP_SERVER_PORT\s*=\s*\).*\$@\1$KMIP_SERVER_PORT@" ~/kbs.env
    sed -i "s@^\(KMIP_CLIENT_CERT_PATH\s*=\s*\).*\$@\1$KMIP_CLIENT_CERT_PATH@" ~/kbs.env
    sed -i "s@^\(KMIP_CLIENT_KEY_PATH\s*=\s*\).*\$@\1$KMIP_CLIENT_KEY_PATH@" ~/kbs.env
    sed -i "s@^\(KMIP_ROOT_CERT_PATH\s*=\s*\).*\$@\1$KMIP_ROOT_CERT_PATH@" ~/kbs.env

    echo "Installing Key Broker Service...."
    (cd $BINARIES_DIR; $SUDO ./kbs-*.bin)
    $SUDO /opt/kbs/bin/kbs status > /dev/null
    if [ $? -ne 0 ]; then
	    echo "Key Broker Service Installation Failed!!"
	    exit 1
    fi
    echo "Installed Key Broker Service."
}

install_pykmip()
{
    sed -i "s@^\(hostname\s*=\s*\).*\$@\1$SYSTEM_IP@" $BINARIES_DIR/server.conf
    sed -i "s@^\(port\s*=\s*\).*\$@\1$KMIP_SERVER_PORT@" $BINARIES_DIR/server.conf

    sed -i "s@^\(KMIP_IP\s*=\s*\).*\$@\1'$SYSTEM_IP'@" $BINARIES_DIR/rsa_create.py
    sed -i "s@^\(SERVER_PORT\s*=\s*\).*\$@\1'$KMIP_SERVER_PORT'@" $BINARIES_DIR/rsa_create.py
    sed -i "s@^\(CERT_PATH\s*=\s*\).*\$@\1'$KMIP_CLIENT_CERT_PATH'@" $BINARIES_DIR/rsa_create.py
    sed -i "s@^\(KEY_PATH\s*=\s*\).*\$@\1'$KMIP_CLIENT_KEY_PATH'@" $BINARIES_DIR/rsa_create.py
    sed -i "s@^\(CA_PATH\s*=\s*\).*\$@\1'$KMIP_ROOT_CERT_PATH'@" $BINARIES_DIR/rsa_create.py

    echo "Installing KMIP Server....."
    export KBS_KMIP_IP=$SYSTEM_IP
    (cd $BINARIES_DIR; $SUDO ./install_pykmip.sh
    if [ $? -ne 0 ]; then
	    echo "KMIP Server Installation Failed!!"
	    exit 1
    fi)
}

clone_repos
build_binaries
copy_binaries
install_pgdb
install_databases
install_cms
install_authservice
populate_users
install_scs
install_sqvs
install_kbs
install_pykmip
