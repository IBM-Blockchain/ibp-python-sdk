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
    import_msp_id = []

# ---------------------------------- Tests ---------------------------------- #
class TestImportMSP():
    def test_import_msp(self):
        opts = {
            'msp_id': 'org1',
            'display_name': 'My First Org',
            'root_certs': [
                'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHVENDQWIrZ0F3SUJBZ0lVY1NLNjBlUE9CNGI1MUIzekZsSnkrYkUzbnlnd0NnWUlLb1pJemowRUF3SXcKWWpFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJNd0VRWURWUVFERXdwdmNtY3hZMkV4CkxXTmhNQjRYRFRJd01UQXhNekUwTlRFd01Gb1hEVE0xTVRBeE1ERTBOVEV3TUZvd1lqRUxNQWtHQTFVRUJoTUMKVlZNeEZ6QVZCZ05WQkFnVERrNXZjblJvSUVOaGNtOXNhVzVoTVJRd0VnWURWUVFLRXd0SWVYQmxjbXhsWkdkbApjakVQTUEwR0ExVUVDeE1HUm1GaWNtbGpNUk13RVFZRFZRUURFd3B2Y21jeFkyRXhMV05oTUZrd0V3WUhLb1pJCnpqMENBUVlJS29aSXpqMERBUWNEUWdBRXpHRmZMdWV6SmxYdDlBa1A3VmNBb0RVeGJvVDBpYUxTTWl4bDRkVi8Kay9sUm5XUUpSdFVZdGk0cWxOQVFqd2JNTlRmWVc2TjQwWG1rdEkxMzRrKyt6cU5UTUZFd0RnWURWUjBQQVFILwpCQVFEQWdFR01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZMbkRDWFNiZXFCc3plYy84Yi9FCmxFcG9hTVhITUE4R0ExVWRFUVFJTUFhSEJIOEFBQUV3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU16T2pBelIKR1lKL3F3eVh5Wm5EVXo2eU53S2VtTFVkendISEwyTU9FZXZ2QWlCd3VMZEZ6VlhubzY0ZEJSMG43czBMdk1XbQo0bTdNRFBZQzJzQlg4K3hIRXc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg'
            ],
            'admins': [
                'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI0ekNDQVlxZ0F3SUJBZ0lVV0J3NHcxMXNVVm9oU0N6WGZ4dWxQVzFRTDFRd0NnWUlLb1pJemowRUF3SXcKWWpFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJNd0VRWURWUVFERXdwdmNtY3hZMkV4CkxXTmhNQjRYRFRJd01UQXhNekUwTlRVd01Gb1hEVEl4TVRBeE16RTFNREF3TUZvd0lERU9NQXdHQTFVRUN4TUYKWVdSdGFXNHhEakFNQmdOVkJBTVRCV0ZrYldsdU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRQo5bVZlM0ZzUlNsTjhKemhDVlhmUHdkci9yc0dyZnlSNzJjUjFGdVRPNnhqVE1TNko5M0hsdUZ2YXdrWUFMUk13CmJFNHZLYXpDVWE0bjkyeDNNVDc5eWFOZ01GNHdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1Bd0dBMVVkRXdFQi93UUMKTUFBd0hRWURWUjBPQkJZRUZFY1lLUTcwU1cvVkZLM210d0M0R3JFUFUzUjlNQjhHQTFVZEl3UVlNQmFBRkxuRApDWFNiZXFCc3plYy84Yi9FbEVwb2FNWEhNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJRnZQWWhNNVNIMmEwSUpoClloem1lN1lrOWlSSDNDOStlNmMrbjkwcHE2bW5BaUJBQlJGSzlPUmJlc2hJb1QrOWxwbENUbVhWelJsenJDR1gKUVE4NS94Ykdudz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K='
            ],
            'tls_root_certs': [
                'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNEVENDQWJTZ0F3SUJBZ0lVVGJwSVdaUlRCcFV3SVhqZW9xQzlKSk56T2NFd0NnWUlLb1pJemowRUF3SXcKWlRFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJZd0ZBWURWUVFERXcxdmNtY3hZMkV4CkxYUnNjMk5oTUI0WERUSXdNVEF4TXpFME5URXdNRm9YRFRNMU1UQXhNREUwTlRFd01Gb3daVEVMTUFrR0ExVUUKQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRS0V3dEllWEJsY214bApaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJZd0ZBWURWUVFERXcxdmNtY3hZMkV4TFhSc2MyTmhNRmt3CkV3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFVS9LZTFMNTdxQlNycTcrK0d3eU5oTTR2eEc2WWtEUVoKNHFMR25yOTBYNTBJYjlOTUhyWVpXam5kNXpoZE5JTlJYZnowOTJDZkYvYlRGM3BuMnRvK3RxTkNNRUF3RGdZRApWUjBQQVFIL0JBUURBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkRzY2lSL3Z1TGcyCmZzQ05jU0dQc1RoUTY5WEFNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJREd4MG5ZVmtRK2Y4T0RmL3lyQUdvSEkKSGhQbU42OUtCL3djRzM2RG5tRWxBaUI3dHczT3pYNldLVmFiSm9XelpRNExWNlJhRnJtMFpPVGhxWk5CbVVSdAo4Zz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
            ]
        }
        response = client.import_msp(**opts)
        assert response.status_code == 200
        assert response.result['timestamp']
        assert response.result['admins']
        assert response.result['display_name'] == 'My First Org'
        assert response.result['id'] == 'myfirstorg'
        assert response.result['location']
        assert response.result['msp_id']
        assert response.result['root_certs']
        assert response.result['scheme_version']
        assert response.result['tags']
        assert response.result['timestamp']
        assert response.result['tls_root_certs']
        assert response.result['type']
        ValueStorage.import_msp_id = response.result['id']

class TestEditMSP():
    def test_edit_a_msp(self):
        response = client.edit_msp(
            id=ValueStorage.import_msp_id,
            display_name='My Other Org'
        )
        assert response.status_code == 200
        assert response.result['timestamp']
        assert response.result['admins']
        assert response.result['display_name'] == 'My Other Org'
        assert response.result['id'] == 'myfirstorg'
        assert response.result['location']
        assert response.result['msp_id']
        assert response.result['root_certs']
        assert response.result['scheme_version']
        assert response.result['tags']
        assert response.result['timestamp']
        assert response.result['tls_root_certs']
        assert response.result['type']

class TestGetMsp():
    def test_get_a_msp(self):
        response = client.get_msp_certificate(
            msp_id='org1',
        )
        assert response.status_code == 200
        assert response.result['msps']
        firstMsp = response.result['msps'][0]
        assert firstMsp['msp_id'] == 'org1'

class TestRemoveMsp():
    def test_remove_a_msp(self):
        response = client.remove_component(
            id=ValueStorage.import_msp_id,
        )
        assert response.status_code == 200
        assert response.result['message'] == 'deleted'
        assert response.result['type'] == 'msp'
        assert response.result['id'] == ValueStorage.import_msp_id
        assert response.result['display_name'] == 'My Other Org'

# clean up tests
class TestRemoveComponents():
    def test_remove_all_components(self):
        response = client.delete_all_components()
        assert response.status_code == 200