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
    created_ca_id = None
    imported_ca_id = None
    imported_peer_id = None
    imported_os_id = None

# ---------------------------------- Tests ---------------------------------- #
class TestRemoveComponents():
    def test_remove_all_components(self):
        response = client.delete_all_components()
        assert response.status_code == 200

class TestClearNotifications():
    def test_clear_notifications(self):
        response = client.delete_all_notifications()
        assert response.status_code == 200

class TestCreateCa():
    def test_create_a_ca(self):
        opts = {
            'display_name': 'My CA',
            'config_override': {
                'ca': {
                    'registry': {
                        'maxenrollments': -1,
                        'identities': [
                            {
                                'name': 'admin',
                                'pass': 'password',
                                'type': 'client',
                                'affiliation': '',
                                'attrs': {
                                    'hf.Registrar.Roles': '*',
                                    'hf.Registrar.DelegateRoles': '*',
                                    'hf.Revoker': True,
                                    'hf.IntermediateCA': True,
                                    'hf.GenCRL': True,
                                    'hf.Registrar.Attributes': '*',
                                    'hf.AffiliationMgr': True
                                }
                            }
                        ]
                    }
                }
            }
        }
        response = client.create_ca(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['dep_component_id']
        assert response.result['display_name']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['resources']
        assert response.result['scheme_version']
        assert response.result['storage']
        assert response.result['tags']
        assert response.result['timestamp']
        assert response.result['version']
        assert response.result['zone']
        assert response.result['display_name'] == 'My CA'
        assert response.result['id'] == 'myca'
        ValueStorage.created_ca_id = response.result['id']

# free clusters cannot update k8s resources
#class TestUpdateCa():
#    def test_update_a_ca(self):
#        opts = {
#            'id': ValueStorage.created_ca_id,
#            'resources': {
#                'ca': {
#                    'requests': {
#                        'cpu': '200m',
#                        'memory': '256Mi'
#                    }
#                }
#            }
#        }
#        response = client.update_ca(**opts)
#        assert response.status_code == 200

class TestGetCa():
    def test_get_a_ca(self):
        opts = {
            'id': ValueStorage.created_ca_id,
            'deployment_attrs': 'included',
            'cache': 'skip'
        }
        response = client.get_component(**opts)
        assert response.status_code == 200
        assert response.result['api_url']
        assert response.result['config_override']
        assert response.result['dep_component_id']
        assert response.result['display_name']
        assert response.result['id']
        assert response.result['location']
        assert response.result['msp']
        assert response.result['operations_url']
        assert response.result['region']
        assert response.result['resources']
        assert response.result['scheme_version']
        assert response.result['storage']
        assert response.result['tags']
        assert response.result['type']
        assert response.result['timestamp']
        assert response.result['version']
        assert response.result['zone']
        assert response.result['id'] == ValueStorage.created_ca_id
        assert response.result['location'] == 'ibm_saas'

class TestRestartCa():
    def test_restart_a_ca(self):
        opts = {
            'id': ValueStorage.created_ca_id,
            'restart': True
        }
        response = client.ca_action(**opts)
        assert response.status_code == 202
        assert response.result['message'] == 'accepted'
        assert response.result['id'] == ValueStorage.created_ca_id

class TestListComponents():
    def test_list_components(self):
        response = client.list_components(deployment_attrs='included')
        firstComp = response.result['components'][0]
        assert response.status_code == 200
        assert firstComp['api_url']
        assert firstComp['config_override']
        assert firstComp['dep_component_id']
        assert firstComp['display_name']
        assert firstComp['id']
        assert firstComp['location']
        assert firstComp['msp']
        assert firstComp['operations_url']
        assert firstComp['region']
        assert firstComp['resources']
        assert firstComp['scheme_version']
        assert firstComp['storage']
        assert firstComp['tags']
        assert firstComp['type']
        assert firstComp['timestamp']
        assert firstComp['version']
        assert firstComp['zone']
        assert firstComp['id'] == ValueStorage.created_ca_id
        assert firstComp['tags'] == ['fabric-ca', 'ibm_saas']

class TestListComponentsNoDep():
    def test_list_components_no_dep_attributes(self):
        response = client.list_components()
        firstComp = response.result['components'][0]
        assert response.status_code == 200
        assert firstComp['api_url']
        assert firstComp['config_override']
        assert firstComp['display_name']
        assert firstComp['id']
        assert firstComp['location']
        assert firstComp['msp']
        assert firstComp['operations_url']
        assert firstComp['scheme_version']
        assert firstComp['tags']
        assert firstComp['type']
        assert firstComp['timestamp']
        assert firstComp['id'] == ValueStorage.created_ca_id

class TestGetAllCas():
    def test_get_all_cas(self):
        response = client.get_components_by_type(
            type='fabric-ca'
        )
        firstComp = response.result['components'][0]
        assert response.status_code == 200
        assert firstComp['id'] == ValueStorage.created_ca_id
        assert firstComp['type'] == 'fabric-ca'

class TestGetSaas():
    def test_get_all_saas_components(self):
        response = client.get_components_by_tag(
            tag='ibm_saas'
        )
        result = response.result['components'][0]
        assert response.status_code == 200
        assert result['id'] == ValueStorage.created_ca_id
        assert result['location'] == 'ibm_saas'

class TestDeleteCa():
    def test_delete_ca(self):
        response = client.delete_component(
            id=ValueStorage.created_ca_id
        )
        assert response.status_code == 200
        assert response.result['message'] == 'deleted'
        assert response.result['type'] == 'fabric-ca'
        assert response.result['id'] == ValueStorage.created_ca_id
        assert response.result['display_name'] == 'My CA'

class TestImportCa():
    def test_import_a_ca(self):
        opts = {
            'display_name': 'My Imported CA',
            'api_url': 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054',
            'operations_url': 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443',
            'location': 'ibmcloud',
            'msp': {
                'ca': {
                    'name': 'ca'
                },
                'tlsca': {
                    'name': 'tlsca'
                },
                'component': {
                    'tls_cert': 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURxVENDQTArZ0F3SUJBZ0lSQUwxQ2lORks1SkxIZGNraGh1bjFETFV3Q2dZSUtvWkl6ajBFQXdJd2dkVXgKQ3pBSkJnTlZCQVlUQWxWVE1SY3dGUVlEVlFRSUV3NU9iM0owYUNCRFlYSnZiR2x1WVRFUE1BMEdBMVVFQnhNRwpSSFZ5YUdGdE1Rd3dDZ1lEVlFRS0V3TkpRazB4RXpBUkJnTlZCQXNUQ2tKc2IyTnJZMmhoYVc0eGVUQjNCZ05WCkJBTVRjR05sYkdSbGNuUmxjM1F4TFc5eVp6RmpZUzFqWVM1alpXeGtaWEl4TFdJell5MDBlREUyTFRNek5HVXgKT1dJMU5qTTBOMlE1WTJVek1tSTJaRFpoT0Rjd1pERTBaak0zTFRBd01EQXVkWE10YzI5MWRHZ3VZMjl1ZEdGcApibVZ5Y3k1aGNIQmtiMjFoYVc0dVkyeHZkV1F3SGhjTk1qQXhNREU0TURFMU5URTNXaGNOTXpBeE1ERTJNREUxCk5URTNXakNCMVRFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1ROHcKRFFZRFZRUUhFd1pFZFhKb1lXMHhEREFLQmdOVkJBb1RBMGxDVFRFVE1CRUdBMVVFQ3hNS1FteHZZMnRqYUdGcApiakY1TUhjR0ExVUVBeE53WTJWc1pHVnlkR1Z6ZERFdGIzSm5NV05oTFdOaExtTmxiR1JsY2pFdFlqTmpMVFI0Ck1UWXRNek0wWlRFNVlqVTJNelEzWkRsalpUTXlZalprTm1FNE56QmtNVFJtTXpjdE1EQXdNQzUxY3kxemIzVjAKYUM1amIyNTBZV2x1WlhKekxtRndjR1J2YldGcGJpNWpiRzkxWkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OQpBd0VIQTBJQUJOYTQxRzRYZGJtT09tY000L2FxaExlYUlPdjZZSHdTOEJqRitFd2lmQW5TYis3U0pma3NmYWNRCmhKS3RvQXRXK2F2SE1vcDFmbVpYS1pQT3lpL2NuWFdqZ2Ywd2dmb3dnZmNHQTFVZEVRU0I3ekNCN0lKd1kyVnMKWkdWeWRHVnpkREV0YjNKbk1XTmhMV05oTG1ObGJHUmxjakV0WWpOakxUUjRNVFl0TXpNMFpURTVZalUyTXpRMwpaRGxqWlRNeVlqWmtObUU0TnpCa01UUm1NemN0TURBd01DNTFjeTF6YjNWMGFDNWpiMjUwWVdsdVpYSnpMbUZ3CmNHUnZiV0ZwYmk1amJHOTFaSUo0WTJWc1pHVnlkR1Z6ZERFdGIzSm5NV05oTFc5d1pYSmhkR2x2Ym5NdVkyVnMKWkdWeU1TMWlNMk10TkhneE5pMHpNelJsTVRsaU5UWXpORGRrT1dObE16SmlObVEyWVRnM01HUXhOR1l6TnkwdwpNREF3TG5WekxYTnZkWFJvTG1OdmJuUmhhVzVsY25NdVlYQndaRzl0WVdsdUxtTnNiM1ZrTUFvR0NDcUdTTTQ5CkJBTUNBMGdBTUVVQ0lFSzZCSWtvamptNm1rbmt0aDgxenIxbU0yM0QzTWhaS2M2QVRRUnZwK3ZHQWlFQXRvcFgKNkJnWlV4NlV0SE5MR3dWKzhDNmwxaEFNQ2YzUnhjRDlQU1ErbUUwPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
                }
            }
        }
        response = client.import_ca(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['timestamp']
        assert response.result['type'] == 'fabric-ca'
        assert response.result['display_name'] == 'My Imported CA'
        ValueStorage.imported_ca_id = response.result['id']

class TestEditDataOnCa():
    def test_edit_data_on_a_ca(self):
        opts = {
            'id': ValueStorage.imported_ca_id,
            'display_name': 'My Other CA',
            'tags': [
                'fabric-ca',
                'ibm_saas',
                'blue_team',
                'dev'
            ]
        }
        response = client.edit_ca(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['timestamp']
        assert response.result['display_name'] == 'My Other CA'
        assert response.result['tags'] == ['blue_team','dev','fabric-ca','ibm_saas']

class TestRemoveImportedCa():
    def test_remove_imported_ca(self):
        response = client.remove_component(id= ValueStorage.imported_ca_id)
        assert response.status_code == 200
        assert response.result['message'] == 'deleted'
        assert response.result['type'] == 'fabric-ca'
        assert response.result['id'] == ValueStorage.imported_ca_id
        assert response.result['display_name'] == 'My Other CA'

class TestRemoveCaByTag():
    def test_import_a_ca(self):

        # first import a ca, then delete it
        opts = {
            'display_name': 'My Second Imported CA',
            'api_url': 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054',
            'operations_url': 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443',
            'location': 'ibmcloud',
            'msp': {
                'ca': {
                    'name': 'ca'
                },
                'tlsca': {
                    'name': 'tlsca'
                },
                'component': {
                    'tls_cert': 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURxVENDQTArZ0F3SUJBZ0lSQUwxQ2lORks1SkxIZGNraGh1bjFETFV3Q2dZSUtvWkl6ajBFQXdJd2dkVXgKQ3pBSkJnTlZCQVlUQWxWVE1SY3dGUVlEVlFRSUV3NU9iM0owYUNCRFlYSnZiR2x1WVRFUE1BMEdBMVVFQnhNRwpSSFZ5YUdGdE1Rd3dDZ1lEVlFRS0V3TkpRazB4RXpBUkJnTlZCQXNUQ2tKc2IyTnJZMmhoYVc0eGVUQjNCZ05WCkJBTVRjR05sYkdSbGNuUmxjM1F4TFc5eVp6RmpZUzFqWVM1alpXeGtaWEl4TFdJell5MDBlREUyTFRNek5HVXgKT1dJMU5qTTBOMlE1WTJVek1tSTJaRFpoT0Rjd1pERTBaak0zTFRBd01EQXVkWE10YzI5MWRHZ3VZMjl1ZEdGcApibVZ5Y3k1aGNIQmtiMjFoYVc0dVkyeHZkV1F3SGhjTk1qQXhNREU0TURFMU5URTNXaGNOTXpBeE1ERTJNREUxCk5URTNXakNCMVRFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1ROHcKRFFZRFZRUUhFd1pFZFhKb1lXMHhEREFLQmdOVkJBb1RBMGxDVFRFVE1CRUdBMVVFQ3hNS1FteHZZMnRqYUdGcApiakY1TUhjR0ExVUVBeE53WTJWc1pHVnlkR1Z6ZERFdGIzSm5NV05oTFdOaExtTmxiR1JsY2pFdFlqTmpMVFI0Ck1UWXRNek0wWlRFNVlqVTJNelEzWkRsalpUTXlZalprTm1FNE56QmtNVFJtTXpjdE1EQXdNQzUxY3kxemIzVjAKYUM1amIyNTBZV2x1WlhKekxtRndjR1J2YldGcGJpNWpiRzkxWkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OQpBd0VIQTBJQUJOYTQxRzRYZGJtT09tY000L2FxaExlYUlPdjZZSHdTOEJqRitFd2lmQW5TYis3U0pma3NmYWNRCmhKS3RvQXRXK2F2SE1vcDFmbVpYS1pQT3lpL2NuWFdqZ2Ywd2dmb3dnZmNHQTFVZEVRU0I3ekNCN0lKd1kyVnMKWkdWeWRHVnpkREV0YjNKbk1XTmhMV05oTG1ObGJHUmxjakV0WWpOakxUUjRNVFl0TXpNMFpURTVZalUyTXpRMwpaRGxqWlRNeVlqWmtObUU0TnpCa01UUm1NemN0TURBd01DNTFjeTF6YjNWMGFDNWpiMjUwWVdsdVpYSnpMbUZ3CmNHUnZiV0ZwYmk1amJHOTFaSUo0WTJWc1pHVnlkR1Z6ZERFdGIzSm5NV05oTFc5d1pYSmhkR2x2Ym5NdVkyVnMKWkdWeU1TMWlNMk10TkhneE5pMHpNelJsTVRsaU5UWXpORGRrT1dObE16SmlObVEyWVRnM01HUXhOR1l6TnkwdwpNREF3TG5WekxYTnZkWFJvTG1OdmJuUmhhVzVsY25NdVlYQndaRzl0WVdsdUxtTnNiM1ZrTUFvR0NDcUdTTTQ5CkJBTUNBMGdBTUVVQ0lFSzZCSWtvamptNm1rbmt0aDgxenIxbU0yM0QzTWhaS2M2QVRRUnZwK3ZHQWlFQXRvcFgKNkJnWlV4NlV0SE5MR3dWKzhDNmwxaEFNQ2YzUnhjRDlQU1ErbUUwPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=='
                }
            },
            'tags': ['my_tag']
        }
        response = client.import_ca(**opts)
        ValueStorage.imported_ca_id = response.result['id']

        # now delete it
        response = client.remove_components_by_tag(tag='my_tag')
        firstComp = response.result['removed'][0]
        assert response.status_code == 200
        assert firstComp['message'] == 'deleted'
        assert firstComp['type'] == 'fabric-ca'
        assert firstComp['id'] == ValueStorage.imported_ca_id
        assert firstComp['display_name'] == 'My Second Imported CA'

class TestImportPeer():
    def test_import_a_peer(self):
        opts = {
            'display_name': 'My Imported Peer',
            'location': 'ibm cloud',
            'api_url': 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051',
            'msp_id': 'PeerOrg1',
            'operations_url': 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443',
            'grpcwp_url': 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084',
            'msp': {
                'component': {
                    'tls_cert': 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K',
                    'ecert': 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K',
                    'admin_certs': [
                        'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
                    ]
                },
                'tlsca': {
                    'root_certs': [
                        'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIvakNDQWFTZ0F3SUJBZ0lVVThuZXFoeWtPQWZaNkN2amhPU2x5Q25XU09rd0NnWUlLb1pJemowRUF3SXcKWFRFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVE0d0RBWURWUVFERXdWMGJITmpZVEFlCkZ3MHlNREF6TVRFeE5qUXpNREJhRncwek5UQXpNRGd4TmpRek1EQmFNRjB4Q3pBSkJnTlZCQVlUQWxWVE1SY3cKRlFZRFZRUUlFdzVPYjNKMGFDQkRZWEp2YkdsdVlURVVNQklHQTFVRUNoTUxTSGx3WlhKc1pXUm5aWEl4RHpBTgpCZ05WQkFzVEJrWmhZbkpwWXpFT01Bd0dBMVVFQXhNRmRHeHpZMkV3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPClBRTUJCd05DQUFUT1dBUEE2N2w1NmFWeW9DRXIyVk00eDBNRW9qNzF0SHJtYjhjTDE1WklJUGdOREIrQzd5NzYKeDBVLzdPNlJta3d0b2d4SnFFU2dWUnJGM1FqalZERTZvMEl3UURBT0JnTlZIUThCQWY4RUJBTUNBUVl3RHdZRApWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVVU5Zk94dW1xakhPMTd2VkR6MnIxcHhHeVJYc3dDZ1lJCktvWkl6ajBFQXdJRFNBQXdSUUloQVBNNVV2STl3MDhhdjRWUG5CckhDbFh3OWJqejEwRTJaOHN1ckZoWnhoY2wKQWlCNm9CWVhPejZWSTl0NVBSekJTV3JMRmZtbUxvQ1p5cXZWMFJ0enNYdi9PZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
                    ]
                },
                'ca': {
                    'root_certs': [
                        'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
                    ]
                }
            }
        }
        response = client.import_peer(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['timestamp']
        assert response.result['type'] == 'fabric-peer'
        assert response.result['display_name'] == 'My Imported Peer'
        ValueStorage.imported_peer_id = response.result['id']

class TestEditDataOnPeer():
    def test_edit_data_on_a_peer(self):
        opts = {
            'id': ValueStorage.imported_peer_id,
            'display_name': 'My Other Peer',
            'tags': [
                'fabric-peer',
                'ibm_saas',
                'red_team',
                'prod'
            ]
        }
        response = client.edit_peer(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['timestamp']
        assert response.result['display_name'] == 'My Other Peer'
        assert response.result['tags'] == ['fabric-peer','ibm_saas', 'prod', 'red_team']

class TestImportOrderer():
    def test_import_a_orderer(self):
        opts = {
            'display_name': 'My Imported Orderer Node',
            'cluster_id': 'abcde',
            'cluster_name': 'My Raft OS',
            'grpcwp_url': 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443',
            'api_url': 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050',
            'operations_url': 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443',
            'msp_id': 'OrdererOrg1',
            'system_channel_id': 'testchainid',
            'msp': {
                'component': {
                    'tls_cert': 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K',
                    'ecert': 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K',
                    'admin_certs': [
                        'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
                    ]
                },
                'tlsca': {
                    'root_certs': [
                        'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIvakNDQWFTZ0F3SUJBZ0lVVThuZXFoeWtPQWZaNkN2amhPU2x5Q25XU09rd0NnWUlLb1pJemowRUF3SXcKWFRFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVE0d0RBWURWUVFERXdWMGJITmpZVEFlCkZ3MHlNREF6TVRFeE5qUXpNREJhRncwek5UQXpNRGd4TmpRek1EQmFNRjB4Q3pBSkJnTlZCQVlUQWxWVE1SY3cKRlFZRFZRUUlFdzVPYjNKMGFDQkRZWEp2YkdsdVlURVVNQklHQTFVRUNoTUxTSGx3WlhKc1pXUm5aWEl4RHpBTgpCZ05WQkFzVEJrWmhZbkpwWXpFT01Bd0dBMVVFQXhNRmRHeHpZMkV3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPClBRTUJCd05DQUFUT1dBUEE2N2w1NmFWeW9DRXIyVk00eDBNRW9qNzF0SHJtYjhjTDE1WklJUGdOREIrQzd5NzYKeDBVLzdPNlJta3d0b2d4SnFFU2dWUnJGM1FqalZERTZvMEl3UURBT0JnTlZIUThCQWY4RUJBTUNBUVl3RHdZRApWUjBUQVFIL0JBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVVU5Zk94dW1xakhPMTd2VkR6MnIxcHhHeVJYc3dDZ1lJCktvWkl6ajBFQXdJRFNBQXdSUUloQVBNNVV2STl3MDhhdjRWUG5CckhDbFh3OWJqejEwRTJaOHN1ckZoWnhoY2wKQWlCNm9CWVhPejZWSTl0NVBSekJTV3JMRmZtbUxvQ1p5cXZWMFJ0enNYdi9PZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
                    ]
                },
                'ca': {
                    'root_certs': [
                        'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNHRENDQWI2Z0F3SUJBZ0lVSENXMzFhSWtxYVkxcFFSbmxPNldNNCtNb2t3d0NnWUlLb1pJemowRUF3SXcKWURFTE1Ba0dBMVVFQmhNQ1ZWTXhGekFWQmdOVkJBZ1REazV2Y25Sb0lFTmhjbTlzYVc1aE1SUXdFZ1lEVlFRSwpFd3RJZVhCbGNteGxaR2RsY2pFUE1BMEdBMVVFQ3hNR1JtRmljbWxqTVJFd0R3WURWUVFERXdoTmVVTkJMWFJzCmN6QWVGdzB4T1RFd01qRXlNREV4TURCYUZ3MHpOREV3TVRjeU1ERXhNREJhTUdBeEN6QUpCZ05WQkFZVEFsVlQKTVJjd0ZRWURWUVFJRXc1T2IzSjBhQ0JEWVhKdmJHbHVZVEVVTUJJR0ExVUVDaE1MU0hsd1pYSnNaV1JuWlhJeApEekFOQmdOVkJBc1RCa1poWW5KcFl6RVJNQThHQTFVRUF4TUlUWGxEUVMxMGJITXdXVEFUQmdjcWhrak9QUUlCCkJnZ3Foa2pPUFFNQkJ3TkNBQVFXYXc3M2FPV3dkMm1zMWxkQ0dBNEVpU212aHFlWTZzYi9RZWxQb0lZMVcwd3QKZ2RCUHFQQkVPN1lvRmdNandndmN1SjZjT3U4YWw0K0pVR0xFcW4wOW8xWXdWREFPQmdOVkhROEJBZjhFQkFNQwpBUVl3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQVRBZEJnTlZIUTRFRmdRVUJhKzhpRUFFeEVHZXUzMzZEV0VLCmZ3ZmtBcFF3RHdZRFZSMFJCQWd3Qm9jRUNsNVRHVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdXozcWs0NEgKMHgrUWNFWk9CVk9pd2pManVFYXZVUEFDZU5CWmVhVkVHM1VDSUZLMjM1bUlwQTF5Q09OTXF2bE40RzI2TnZuWApvUFk4TDJGeWY3aTg0bm9lCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K'
                    ]
                }
            }
        }
        response = client.import_orderer(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['timestamp']
        assert response.result['type'] == 'fabric-orderer'
        assert response.result['display_name'] == 'My Imported Orderer Node'
        ValueStorage.imported_os_id = response.result['id']

class TestEditDataOnOrderer():
    def test_edit_data_on_a_peer(self):
        opts = {
            'id': ValueStorage.imported_os_id,
            'cluster_name': 'My Other OS',
            'display_name': 'My Other Imported Orderer Node',
            'msp_id': 'orderermsp'
        }
        response = client.edit_orderer(**opts)
        assert response.status_code == 200
        assert response.result['id']
        assert response.result['api_url']
        assert response.result['operations_url']
        assert response.result['msp']
        assert response.result['timestamp']
        assert response.result['display_name'] == 'My Other Imported Orderer Node'
