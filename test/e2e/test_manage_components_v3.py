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

# ---------------------------------- Tests ---------------------------------- #
class TestRemoveComponents():
    def test_remove_all_components(self):
        # Invoke method
        response = client.delete_all_components()

        # Check for correct operation
        assert response.status_code == 200

class TestClearNotifications():
    def test_clear_notifications(self):
        # Invoke method
        response = client.delete_all_notifications()

        # Check for correct operation
        assert response.status_code == 200

class TestListComponents():
    def test_list_components_all_params(self):
        # Invoke method
        response = client.list_components(
            deployment_attrs='included',
            parsed_certs='included',
            cache='skip',
            ca_attrs='included',
            headers={}
        )

        # Check for correct operation
        assert response.status_code == 200

