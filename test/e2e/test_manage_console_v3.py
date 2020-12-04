# -*- coding: utf-8 -*-
# (C) Copyright IBM Corp. 2020.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
NOTE: running this requires setting up a living IBP Console on IBM Cloud Staging
- pass the IAM api key to use via GitHub secret "IAM_API_KEY"
- pass the IBP Console url to use via GitHub secret "IBP_SERVICE_INSTANCE_URL"
"""

import inspect
import json
import pytest

# dumb hack to load the relative file up two levels
import sys
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(
        __file__), os.path.pardir, os.path.pardir))
)
from ibp_python_sdk import *        # must be last

# ---------------------------------
# read file for local secrets (local mode only), else use env vars
siid_url = ''
apikey = ''
try:
    with open('./test/e2e/davids_secrets.json', 'r') as secrets:
        data = secrets.read()
    obj = json.loads(data)
    siid_url = obj["url"]
    apikey = obj["apikey"]
    print(f'siid_url:\n {siid_url}')
    print(f'apikey:\n {apikey}')
except Exception as e:
    # if we fail to load the local file pull from env
    siid_url = os.environ['IBP_SERVICE_INSTANCE_URL']
    apikey = os.environ['IAM_API_KEY']
# ---------------------------------

# Create an authenticator
authenticator = IAMAuthenticator(
    # use staging IAM url
    url='https://identity-1.us-south.iam.test.cloud.ibm.com/identity/token',
    apikey=apikey,
)

# Create client from the "BlockchainV3" class
client = BlockchainV3(authenticator=authenticator)
client.set_service_url(siid_url)


# temp vars
class ValueStorage:
    notifications = []

# ---------------------------------- Tests ---------------------------------- #
class TestIBPSettings():
    def test_get_ibp_settings(self):
        response = client.get_settings()
        assert response.status_code == 200
        assert response.result['ACTIVITY_TRACKER_PATH']
        assert response.result['ATHENA_ID']
        assert response.result['AUTH_SCHEME']
        assert response.result['CALLBACK_URI']
        assert response.result['CLUSTER_DATA']
        assert response.result['CONFIGTXLATOR_URL']
        assert response.result['CRN']
        assert response.result['CRN_STRING']
        assert response.result['CSP_HEADER_VALUES']
        assert response.result['DB_SYSTEM']
        assert response.result['DEPLOYER_URL']
        assert response.result['DOMAIN']
        assert response.result['ENVIRONMENT']
        assert response.result['FABRIC_CAPABILITIES']
        assert response.result['FEATURE_FLAGS']
        assert response.result['FILE_LOGGING']
        assert response.result['HOST_URL']
        assert response.result['IAM_CACHE_ENABLED']
        assert response.result['IAM_URL']
        assert response.result['IBM_ID_CALLBACK_URL']
        assert response.result['IGNORE_CONFIG_FILE']
        assert response.result['INACTIVITY_TIMEOUTS']
        assert response.result['INFRASTRUCTURE']
        assert response.result['LANDING_URL']
        assert response.result['LOGIN_URI']
        assert response.result['LOGOUT_URI']
        assert response.result['MAX_REQ_PER_MIN']
        assert response.result['MAX_REQ_PER_MIN_AK']
        assert response.result['MEMORY_CACHE_ENABLED']
        assert response.result['PORT']
        assert response.result['PROXY_CACHE_ENABLED']
        assert response.result['PROXY_TLS_FABRIC_REQS']
        assert response.result['PROXY_TLS_HTTP_URL']
        assert response.result['PROXY_TLS_WS_URL']
        assert response.result['REGION']
        assert response.result['SESSION_CACHE_ENABLED'] == True or response.result['SESSION_CACHE_ENABLED'] == False
        assert response.result['TIMEOUTS']
        assert response.result['TIMESTAMPS']
        #assert response.result['TRANSACTION_VISIBILITY']
        assert response.result['TRUST_PROXY']
        assert response.result['TRUST_UNKNOWN_CERTS'] == True or response.result['TRUST_UNKNOWN_CERTS'] == False
        assert response.result['VERSIONS']

        assert response.result['VERSIONS']['apollo']
        assert response.result['VERSIONS']['athena']
        assert response.result['VERSIONS']['stitch']
        assert response.result['VERSIONS']['tag']

class TestSupportedFabric():
    def test_get_supported_fabric_versions(self):
        response = client.get_fab_versions()
        assert response.status_code == 200
        assert response.result['versions']
        assert response.result['versions']['ca']
        assert response.result['versions']['peer']
        assert response.result['versions']['orderer']

class TestIBPHealth():
    def test_get_ibp_console_health(self):
        response = client.get_health()
        assert response.status_code == 200
        assert response.result['OPTOOLS']
        assert response.result['OS']

class TestIBPNotifications():
    def test_get_ibp_console_notifications(self):
        response = client.list_notifications(limit=3, skip=1)
        assert response.status_code == 200
        assert response.result['total']
        assert response.result['returning']
        assert response.result['notifications']
        ValueStorage.notifications = response.result['notifications']

class TestArchiveNotifictions():
    def test_get_ibp_console_notifications(self):

        ids = []
        for x in ValueStorage.notifications:
            ids.append(x['id'])

        response = client.archive_notifications(notification_ids=ids)
        assert response.status_code == 200
        assert response.result['message']
        assert response.result['details']

# commented out b/c create api not exposed yet
# class TestDeleteSigCollection():
#    def test_delete_signature_collection(self):
#        response = client.delete_sig_tx(id='abc')
#        assert response.status_code == 200

# commented out b/c this restarts IBP and screws up other tests
# class TestIBPRestart():
#    def test_restart_ibp_console(self):
#        response = client.restart()
#        assert response.status_code == 200

class TestDeleteAllIBPConsoleSessions():
    def test_get_ibp_console_notifications(self):
        response = client.delete_all_sessions()
        assert response.status_code == 202
        assert response.result['message']
        assert response.result['message'] == 'delete submitted'

class TestDeleteAllIBPNotifications():
    def test_delete_ibp_console_notifications(self):
        response = client.delete_all_notifications()
        assert response.status_code == 200
        assert response.result['message']
        assert response.result['details']

class TestDeleteIBPCache():
    def test_delete_all_ibp_console_caches(self):
        response = client.clear_caches()
        assert response.status_code == 200
        assert response.result['message']
        assert response.result['flushed']

class TestGetPostman():
    def test_get_postman_collection(self):
        opts = {
            'auth_type': 'api_key',
            'api_key': '{API-Key}'
        }
        response = client.get_postman(**opts)
        assert response.status_code == 200

class TestGetOpenAPI():
    def test_get_postman_collection(self):
        response = client.get_swagger()
        assert response.status_code == 200