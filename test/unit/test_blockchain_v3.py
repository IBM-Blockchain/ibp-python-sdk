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

from ibm_cloud_sdk_core.authenticators.no_auth_authenticator import NoAuthAuthenticator
import inspect
import json
import pytest
import re
import requests
import responses

# dumb hack to load the relative file up two levels
import sys
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir))
)
from ibp_python_sdk import *

service = BlockchainV3(
    authenticator=NoAuthAuthenticator()
    )

base_url = 'https://fake'
service.set_service_url(base_url)

##############################################################################
# Start of Service: ManageComponent
##############################################################################
# region

#-----------------------------------------------------------------------------
# Test Class for get_component
#-----------------------------------------------------------------------------
class TestGetComponent():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_component()
    #--------------------------------------------------------
    @responses.activate
    def test_get_component_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/testString')
        mock_response = '{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        deployment_attrs = 'included'
        parsed_certs = 'included'
        cache = 'skip'
        ca_attrs = 'included'

        # Invoke method
        response = service.get_component(
            id,
            deployment_attrs=deployment_attrs,
            parsed_certs=parsed_certs,
            cache=cache,
            ca_attrs=ca_attrs,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'deployment_attrs={}'.format(deployment_attrs) in query_string
        assert 'parsed_certs={}'.format(parsed_certs) in query_string
        assert 'cache={}'.format(cache) in query_string
        assert 'ca_attrs={}'.format(ca_attrs) in query_string


    #--------------------------------------------------------
    # test_get_component_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_get_component_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/testString')
        mock_response = '{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.get_component(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_get_component_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_get_component_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/testString')
        mock_response = '{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_component(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for remove_component
#-----------------------------------------------------------------------------
class TestRemoveComponent():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # remove_component()
    #--------------------------------------------------------
    @responses.activate
    def test_remove_component_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/testString')
        mock_response = '{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.remove_component(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_remove_component_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_remove_component_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/testString')
        mock_response = '{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.remove_component(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for delete_component
#-----------------------------------------------------------------------------
class TestDeleteComponent():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # delete_component()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_component_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString')
        mock_response = '{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.delete_component(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_delete_component_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_component_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString')
        mock_response = '{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.delete_component(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for create_ca
#-----------------------------------------------------------------------------
class TestCreateCa():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # create_ca()
    #--------------------------------------------------------
    @responses.activate
    def test_create_ca_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-ca')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigCASigningProfilesCaCaconstraint model
        config_ca_signing_profiles_ca_caconstraint_model = {}
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        # Construct a dict representation of a ConfigCADbTlsClient model
        config_ca_db_tls_client_model = {}
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTlsClient model
        config_ca_intermediate_tls_client_model = {}
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a ConfigCASigningProfilesCa model
        config_ca_signing_profiles_ca_model = {}
        config_ca_signing_profiles_ca_model['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        # Construct a dict representation of a ConfigCASigningProfilesTls model
        config_ca_signing_profiles_tls_model = {}
        config_ca_signing_profiles_tls_model['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model['expiry'] = '43800h'

        # Construct a dict representation of a IdentityAttrs model
        identity_attrs_model = {}
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a ConfigCACfgIdentities model
        config_ca_cfg_identities_model = {}
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        # Construct a dict representation of a ConfigCACsrCa model
        config_ca_csr_ca_model = {}
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        # Construct a dict representation of a ConfigCACsrKeyrequest model
        config_ca_csr_keyrequest_model = {}
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        # Construct a dict representation of a ConfigCACsrNamesItem model
        config_ca_csr_names_item_model = {}
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        # Construct a dict representation of a ConfigCADbTls model
        config_ca_db_tls_model = {}
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        # Construct a dict representation of a ConfigCAIntermediateEnrollment model
        config_ca_intermediate_enrollment_model = {}
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateParentserver model
        config_ca_intermediate_parentserver_model = {}
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTls model
        config_ca_intermediate_tls_model = {}
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        # Construct a dict representation of a ConfigCARegistryIdentitiesItem model
        config_ca_registry_identities_item_model = {}
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        # Construct a dict representation of a ConfigCASigningDefault model
        config_ca_signing_default_model = {}
        config_ca_signing_default_model['usage'] = ['cert sign']
        config_ca_signing_default_model['expiry'] = '8760h'

        # Construct a dict representation of a ConfigCASigningProfiles model
        config_ca_signing_profiles_model = {}
        config_ca_signing_profiles_model['ca'] = config_ca_signing_profiles_ca_model
        config_ca_signing_profiles_model['tls'] = config_ca_signing_profiles_tls_model

        # Construct a dict representation of a ConfigCATlsClientauth model
        config_ca_tls_clientauth_model = {}
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigCAAffiliations model
        config_ca_affiliations_model = {}
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        # Construct a dict representation of a ConfigCACa model
        config_ca_ca_model = {}
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        # Construct a dict representation of a ConfigCACfg model
        config_ca_cfg_model = {}
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        # Construct a dict representation of a ConfigCACors model
        config_ca_cors_model = {}
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        # Construct a dict representation of a ConfigCACrl model
        config_ca_crl_model = {}
        config_ca_crl_model['expiry'] = '24h'

        # Construct a dict representation of a ConfigCACsr model
        config_ca_csr_model = {}
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        # Construct a dict representation of a ConfigCADb model
        config_ca_db_model = {}
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        # Construct a dict representation of a ConfigCAIdemix model
        config_ca_idemix_model = {}
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        # Construct a dict representation of a ConfigCAIntermediate model
        config_ca_intermediate_model = {}
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        # Construct a dict representation of a ConfigCARegistry model
        config_ca_registry_model = {}
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        # Construct a dict representation of a ConfigCASigning model
        config_ca_signing_model = {}
        config_ca_signing_model['default'] = config_ca_signing_default_model
        config_ca_signing_model['profiles'] = config_ca_signing_profiles_model

        # Construct a dict representation of a ConfigCATls model
        config_ca_tls_model = {}
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigCACreate model
        config_ca_create_model = {}
        config_ca_create_model['cors'] = config_ca_cors_model
        config_ca_create_model['debug'] = False
        config_ca_create_model['crlsizelimit'] = 512000
        config_ca_create_model['tls'] = config_ca_tls_model
        config_ca_create_model['ca'] = config_ca_ca_model
        config_ca_create_model['crl'] = config_ca_crl_model
        config_ca_create_model['registry'] = config_ca_registry_model
        config_ca_create_model['db'] = config_ca_db_model
        config_ca_create_model['affiliations'] = config_ca_affiliations_model
        config_ca_create_model['csr'] = config_ca_csr_model
        config_ca_create_model['idemix'] = config_ca_idemix_model
        config_ca_create_model['BCCSP'] = bccsp_model
        config_ca_create_model['intermediate'] = config_ca_intermediate_model
        config_ca_create_model['cfg'] = config_ca_cfg_model
        config_ca_create_model['metrics'] = metrics_model
        config_ca_create_model['signing'] = config_ca_signing_model

        # Construct a dict representation of a CreateCaBodyConfigOverride model
        create_ca_body_config_override_model = {}
        create_ca_body_config_override_model['ca'] = config_ca_create_model
        create_ca_body_config_override_model['tlsca'] = config_ca_create_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a CreateCaBodyResources model
        create_ca_body_resources_model = {}
        create_ca_body_resources_model['ca'] = resource_object_model

        # Construct a dict representation of a StorageObject model
        storage_object_model = {}
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a dict representation of a CreateCaBodyStorage model
        create_ca_body_storage_model = {}
        create_ca_body_storage_model['ca'] = storage_object_model

        # Construct a dict representation of a Hsm model
        hsm_model = {}
        hsm_model['pkcs11endpoint'] = 'tcp://example.com:666'

        # Set up parameter values
        display_name = 'My CA'
        config_override = create_ca_body_config_override_model
        resources = create_ca_body_resources_model
        storage = create_ca_body_storage_model
        zone = '-'
        replicas = 1
        tags = ['fabric-ca']
        hsm = hsm_model
        region = '-'
        version = '1.4.6-1'

        # Invoke method
        response = service.create_ca(
            display_name,
            config_override,
            resources=resources,
            storage=storage,
            zone=zone,
            replicas=replicas,
            tags=tags,
            hsm=hsm,
            region=region,
            version=version,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['display_name'] == 'My CA'
        assert req_body['config_override'] == create_ca_body_config_override_model
        assert req_body['resources'] == create_ca_body_resources_model
        assert req_body['storage'] == create_ca_body_storage_model
        assert req_body['zone'] == '-'
        assert req_body['replicas'] == 1
        assert req_body['tags'] == ['fabric-ca']
        assert req_body['hsm'] == hsm_model
        assert req_body['region'] == '-'
        assert req_body['version'] == '1.4.6-1'


    #--------------------------------------------------------
    # test_create_ca_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_create_ca_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-ca')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigCASigningProfilesCaCaconstraint model
        config_ca_signing_profiles_ca_caconstraint_model = {}
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        # Construct a dict representation of a ConfigCADbTlsClient model
        config_ca_db_tls_client_model = {}
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTlsClient model
        config_ca_intermediate_tls_client_model = {}
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a ConfigCASigningProfilesCa model
        config_ca_signing_profiles_ca_model = {}
        config_ca_signing_profiles_ca_model['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        # Construct a dict representation of a ConfigCASigningProfilesTls model
        config_ca_signing_profiles_tls_model = {}
        config_ca_signing_profiles_tls_model['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model['expiry'] = '43800h'

        # Construct a dict representation of a IdentityAttrs model
        identity_attrs_model = {}
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a ConfigCACfgIdentities model
        config_ca_cfg_identities_model = {}
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        # Construct a dict representation of a ConfigCACsrCa model
        config_ca_csr_ca_model = {}
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        # Construct a dict representation of a ConfigCACsrKeyrequest model
        config_ca_csr_keyrequest_model = {}
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        # Construct a dict representation of a ConfigCACsrNamesItem model
        config_ca_csr_names_item_model = {}
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        # Construct a dict representation of a ConfigCADbTls model
        config_ca_db_tls_model = {}
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        # Construct a dict representation of a ConfigCAIntermediateEnrollment model
        config_ca_intermediate_enrollment_model = {}
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateParentserver model
        config_ca_intermediate_parentserver_model = {}
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTls model
        config_ca_intermediate_tls_model = {}
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        # Construct a dict representation of a ConfigCARegistryIdentitiesItem model
        config_ca_registry_identities_item_model = {}
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        # Construct a dict representation of a ConfigCASigningDefault model
        config_ca_signing_default_model = {}
        config_ca_signing_default_model['usage'] = ['cert sign']
        config_ca_signing_default_model['expiry'] = '8760h'

        # Construct a dict representation of a ConfigCASigningProfiles model
        config_ca_signing_profiles_model = {}
        config_ca_signing_profiles_model['ca'] = config_ca_signing_profiles_ca_model
        config_ca_signing_profiles_model['tls'] = config_ca_signing_profiles_tls_model

        # Construct a dict representation of a ConfigCATlsClientauth model
        config_ca_tls_clientauth_model = {}
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigCAAffiliations model
        config_ca_affiliations_model = {}
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        # Construct a dict representation of a ConfigCACa model
        config_ca_ca_model = {}
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        # Construct a dict representation of a ConfigCACfg model
        config_ca_cfg_model = {}
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        # Construct a dict representation of a ConfigCACors model
        config_ca_cors_model = {}
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        # Construct a dict representation of a ConfigCACrl model
        config_ca_crl_model = {}
        config_ca_crl_model['expiry'] = '24h'

        # Construct a dict representation of a ConfigCACsr model
        config_ca_csr_model = {}
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        # Construct a dict representation of a ConfigCADb model
        config_ca_db_model = {}
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        # Construct a dict representation of a ConfigCAIdemix model
        config_ca_idemix_model = {}
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        # Construct a dict representation of a ConfigCAIntermediate model
        config_ca_intermediate_model = {}
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        # Construct a dict representation of a ConfigCARegistry model
        config_ca_registry_model = {}
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        # Construct a dict representation of a ConfigCASigning model
        config_ca_signing_model = {}
        config_ca_signing_model['default'] = config_ca_signing_default_model
        config_ca_signing_model['profiles'] = config_ca_signing_profiles_model

        # Construct a dict representation of a ConfigCATls model
        config_ca_tls_model = {}
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigCACreate model
        config_ca_create_model = {}
        config_ca_create_model['cors'] = config_ca_cors_model
        config_ca_create_model['debug'] = False
        config_ca_create_model['crlsizelimit'] = 512000
        config_ca_create_model['tls'] = config_ca_tls_model
        config_ca_create_model['ca'] = config_ca_ca_model
        config_ca_create_model['crl'] = config_ca_crl_model
        config_ca_create_model['registry'] = config_ca_registry_model
        config_ca_create_model['db'] = config_ca_db_model
        config_ca_create_model['affiliations'] = config_ca_affiliations_model
        config_ca_create_model['csr'] = config_ca_csr_model
        config_ca_create_model['idemix'] = config_ca_idemix_model
        config_ca_create_model['BCCSP'] = bccsp_model
        config_ca_create_model['intermediate'] = config_ca_intermediate_model
        config_ca_create_model['cfg'] = config_ca_cfg_model
        config_ca_create_model['metrics'] = metrics_model
        config_ca_create_model['signing'] = config_ca_signing_model

        # Construct a dict representation of a CreateCaBodyConfigOverride model
        create_ca_body_config_override_model = {}
        create_ca_body_config_override_model['ca'] = config_ca_create_model
        create_ca_body_config_override_model['tlsca'] = config_ca_create_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a CreateCaBodyResources model
        create_ca_body_resources_model = {}
        create_ca_body_resources_model['ca'] = resource_object_model

        # Construct a dict representation of a StorageObject model
        storage_object_model = {}
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a dict representation of a CreateCaBodyStorage model
        create_ca_body_storage_model = {}
        create_ca_body_storage_model['ca'] = storage_object_model

        # Construct a dict representation of a Hsm model
        hsm_model = {}
        hsm_model['pkcs11endpoint'] = 'tcp://example.com:666'

        # Set up parameter values
        display_name = 'My CA'
        config_override = create_ca_body_config_override_model
        resources = create_ca_body_resources_model
        storage = create_ca_body_storage_model
        zone = '-'
        replicas = 1
        tags = ['fabric-ca']
        hsm = hsm_model
        region = '-'
        version = '1.4.6-1'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "display_name": display_name,
            "config_override": config_override,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.create_ca(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for import_ca
#-----------------------------------------------------------------------------
class TestImportCa():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # import_ca()
    #--------------------------------------------------------
    @responses.activate
    def test_import_ca_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-ca')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ImportCaBodyMspCa model
        import_ca_body_msp_ca_model = {}
        import_ca_body_msp_ca_model['name'] = 'org1CA'
        import_ca_body_msp_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a ImportCaBodyMspComponent model
        import_ca_body_msp_component_model = {}
        import_ca_body_msp_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='

        # Construct a dict representation of a ImportCaBodyMspTlsca model
        import_ca_body_msp_tlsca_model = {}
        import_ca_body_msp_tlsca_model['name'] = 'org1tlsCA'
        import_ca_body_msp_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a ImportCaBodyMsp model
        import_ca_body_msp_model = {}
        import_ca_body_msp_model['ca'] = import_ca_body_msp_ca_model
        import_ca_body_msp_model['tlsca'] = import_ca_body_msp_tlsca_model
        import_ca_body_msp_model['component'] = import_ca_body_msp_component_model

        # Set up parameter values
        display_name = 'Sample CA'
        api_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054'
        msp = import_ca_body_msp_model
        location = 'ibmcloud'
        operations_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        tags = ['fabric-ca']
        tls_cert = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='

        # Invoke method
        response = service.import_ca(
            display_name,
            api_url,
            msp,
            location=location,
            operations_url=operations_url,
            tags=tags,
            tls_cert=tls_cert,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['display_name'] == 'Sample CA'
        assert req_body['api_url'] == 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054'
        assert req_body['msp'] == import_ca_body_msp_model
        assert req_body['location'] == 'ibmcloud'
        assert req_body['operations_url'] == 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        assert req_body['tags'] == ['fabric-ca']
        assert req_body['tls_cert'] == 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='


    #--------------------------------------------------------
    # test_import_ca_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_import_ca_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-ca')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ImportCaBodyMspCa model
        import_ca_body_msp_ca_model = {}
        import_ca_body_msp_ca_model['name'] = 'org1CA'
        import_ca_body_msp_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a ImportCaBodyMspComponent model
        import_ca_body_msp_component_model = {}
        import_ca_body_msp_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='

        # Construct a dict representation of a ImportCaBodyMspTlsca model
        import_ca_body_msp_tlsca_model = {}
        import_ca_body_msp_tlsca_model['name'] = 'org1tlsCA'
        import_ca_body_msp_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a ImportCaBodyMsp model
        import_ca_body_msp_model = {}
        import_ca_body_msp_model['ca'] = import_ca_body_msp_ca_model
        import_ca_body_msp_model['tlsca'] = import_ca_body_msp_tlsca_model
        import_ca_body_msp_model['component'] = import_ca_body_msp_component_model

        # Set up parameter values
        display_name = 'Sample CA'
        api_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054'
        msp = import_ca_body_msp_model
        location = 'ibmcloud'
        operations_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        tags = ['fabric-ca']
        tls_cert = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "display_name": display_name,
            "api_url": api_url,
            "msp": msp,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.import_ca(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for update_ca
#-----------------------------------------------------------------------------
class TestUpdateCa():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # update_ca()
    #--------------------------------------------------------
    @responses.activate
    def test_update_ca_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-ca/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigCADbTlsClient model
        config_ca_db_tls_client_model = {}
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTlsClient model
        config_ca_intermediate_tls_client_model = {}
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a IdentityAttrs model
        identity_attrs_model = {}
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a ConfigCACfgIdentities model
        config_ca_cfg_identities_model = {}
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        # Construct a dict representation of a ConfigCACsrCa model
        config_ca_csr_ca_model = {}
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        # Construct a dict representation of a ConfigCACsrKeyrequest model
        config_ca_csr_keyrequest_model = {}
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        # Construct a dict representation of a ConfigCACsrNamesItem model
        config_ca_csr_names_item_model = {}
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        # Construct a dict representation of a ConfigCADbTls model
        config_ca_db_tls_model = {}
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        # Construct a dict representation of a ConfigCAIntermediateEnrollment model
        config_ca_intermediate_enrollment_model = {}
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateParentserver model
        config_ca_intermediate_parentserver_model = {}
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTls model
        config_ca_intermediate_tls_model = {}
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        # Construct a dict representation of a ConfigCARegistryIdentitiesItem model
        config_ca_registry_identities_item_model = {}
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        # Construct a dict representation of a ConfigCATlsClientauth model
        config_ca_tls_clientauth_model = {}
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigCAAffiliations model
        config_ca_affiliations_model = {}
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        # Construct a dict representation of a ConfigCACa model
        config_ca_ca_model = {}
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        # Construct a dict representation of a ConfigCACfg model
        config_ca_cfg_model = {}
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        # Construct a dict representation of a ConfigCACors model
        config_ca_cors_model = {}
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        # Construct a dict representation of a ConfigCACrl model
        config_ca_crl_model = {}
        config_ca_crl_model['expiry'] = '24h'

        # Construct a dict representation of a ConfigCACsr model
        config_ca_csr_model = {}
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        # Construct a dict representation of a ConfigCADb model
        config_ca_db_model = {}
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        # Construct a dict representation of a ConfigCAIdemix model
        config_ca_idemix_model = {}
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        # Construct a dict representation of a ConfigCAIntermediate model
        config_ca_intermediate_model = {}
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        # Construct a dict representation of a ConfigCARegistry model
        config_ca_registry_model = {}
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        # Construct a dict representation of a ConfigCATls model
        config_ca_tls_model = {}
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigCAUpdate model
        config_ca_update_model = {}
        config_ca_update_model['cors'] = config_ca_cors_model
        config_ca_update_model['debug'] = False
        config_ca_update_model['crlsizelimit'] = 512000
        config_ca_update_model['tls'] = config_ca_tls_model
        config_ca_update_model['ca'] = config_ca_ca_model
        config_ca_update_model['crl'] = config_ca_crl_model
        config_ca_update_model['registry'] = config_ca_registry_model
        config_ca_update_model['db'] = config_ca_db_model
        config_ca_update_model['affiliations'] = config_ca_affiliations_model
        config_ca_update_model['csr'] = config_ca_csr_model
        config_ca_update_model['idemix'] = config_ca_idemix_model
        config_ca_update_model['BCCSP'] = bccsp_model
        config_ca_update_model['intermediate'] = config_ca_intermediate_model
        config_ca_update_model['cfg'] = config_ca_cfg_model
        config_ca_update_model['metrics'] = metrics_model

        # Construct a dict representation of a UpdateCaBodyConfigOverride model
        update_ca_body_config_override_model = {}
        update_ca_body_config_override_model['ca'] = config_ca_update_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a UpdateCaBodyResources model
        update_ca_body_resources_model = {}
        update_ca_body_resources_model['ca'] = resource_object_model

        # Set up parameter values
        id = 'testString'
        config_override = update_ca_body_config_override_model
        replicas = 1
        resources = update_ca_body_resources_model
        version = '1.4.6-1'
        zone = '-'

        # Invoke method
        response = service.update_ca(
            id,
            config_override=config_override,
            replicas=replicas,
            resources=resources,
            version=version,
            zone=zone,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['config_override'] == update_ca_body_config_override_model
        assert req_body['replicas'] == 1
        assert req_body['resources'] == update_ca_body_resources_model
        assert req_body['version'] == '1.4.6-1'
        assert req_body['zone'] == '-'


    #--------------------------------------------------------
    # test_update_ca_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_update_ca_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-ca/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigCADbTlsClient model
        config_ca_db_tls_client_model = {}
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTlsClient model
        config_ca_intermediate_tls_client_model = {}
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        # Construct a dict representation of a IdentityAttrs model
        identity_attrs_model = {}
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a ConfigCACfgIdentities model
        config_ca_cfg_identities_model = {}
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        # Construct a dict representation of a ConfigCACsrCa model
        config_ca_csr_ca_model = {}
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        # Construct a dict representation of a ConfigCACsrKeyrequest model
        config_ca_csr_keyrequest_model = {}
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        # Construct a dict representation of a ConfigCACsrNamesItem model
        config_ca_csr_names_item_model = {}
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        # Construct a dict representation of a ConfigCADbTls model
        config_ca_db_tls_model = {}
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        # Construct a dict representation of a ConfigCAIntermediateEnrollment model
        config_ca_intermediate_enrollment_model = {}
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateParentserver model
        config_ca_intermediate_parentserver_model = {}
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        # Construct a dict representation of a ConfigCAIntermediateTls model
        config_ca_intermediate_tls_model = {}
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        # Construct a dict representation of a ConfigCARegistryIdentitiesItem model
        config_ca_registry_identities_item_model = {}
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        # Construct a dict representation of a ConfigCATlsClientauth model
        config_ca_tls_clientauth_model = {}
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigCAAffiliations model
        config_ca_affiliations_model = {}
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        # Construct a dict representation of a ConfigCACa model
        config_ca_ca_model = {}
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        # Construct a dict representation of a ConfigCACfg model
        config_ca_cfg_model = {}
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        # Construct a dict representation of a ConfigCACors model
        config_ca_cors_model = {}
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        # Construct a dict representation of a ConfigCACrl model
        config_ca_crl_model = {}
        config_ca_crl_model['expiry'] = '24h'

        # Construct a dict representation of a ConfigCACsr model
        config_ca_csr_model = {}
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        # Construct a dict representation of a ConfigCADb model
        config_ca_db_model = {}
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        # Construct a dict representation of a ConfigCAIdemix model
        config_ca_idemix_model = {}
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        # Construct a dict representation of a ConfigCAIntermediate model
        config_ca_intermediate_model = {}
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        # Construct a dict representation of a ConfigCARegistry model
        config_ca_registry_model = {}
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        # Construct a dict representation of a ConfigCATls model
        config_ca_tls_model = {}
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigCAUpdate model
        config_ca_update_model = {}
        config_ca_update_model['cors'] = config_ca_cors_model
        config_ca_update_model['debug'] = False
        config_ca_update_model['crlsizelimit'] = 512000
        config_ca_update_model['tls'] = config_ca_tls_model
        config_ca_update_model['ca'] = config_ca_ca_model
        config_ca_update_model['crl'] = config_ca_crl_model
        config_ca_update_model['registry'] = config_ca_registry_model
        config_ca_update_model['db'] = config_ca_db_model
        config_ca_update_model['affiliations'] = config_ca_affiliations_model
        config_ca_update_model['csr'] = config_ca_csr_model
        config_ca_update_model['idemix'] = config_ca_idemix_model
        config_ca_update_model['BCCSP'] = bccsp_model
        config_ca_update_model['intermediate'] = config_ca_intermediate_model
        config_ca_update_model['cfg'] = config_ca_cfg_model
        config_ca_update_model['metrics'] = metrics_model

        # Construct a dict representation of a UpdateCaBodyConfigOverride model
        update_ca_body_config_override_model = {}
        update_ca_body_config_override_model['ca'] = config_ca_update_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a UpdateCaBodyResources model
        update_ca_body_resources_model = {}
        update_ca_body_resources_model['ca'] = resource_object_model

        # Set up parameter values
        id = 'testString'
        config_override = update_ca_body_config_override_model
        replicas = 1
        resources = update_ca_body_resources_model
        version = '1.4.6-1'
        zone = '-'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.update_ca(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for edit_ca
#-----------------------------------------------------------------------------
class TestEditCa():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # edit_ca()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_ca_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-ca/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        display_name = 'My CA'
        api_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054'
        operations_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        ca_name = 'ca'
        location = 'ibmcloud'
        tags = ['fabric-ca']

        # Invoke method
        response = service.edit_ca(
            id,
            display_name=display_name,
            api_url=api_url,
            operations_url=operations_url,
            ca_name=ca_name,
            location=location,
            tags=tags,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['display_name'] == 'My CA'
        assert req_body['api_url'] == 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054'
        assert req_body['operations_url'] == 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        assert req_body['ca_name'] == 'ca'
        assert req_body['location'] == 'ibmcloud'
        assert req_body['tags'] == ['fabric-ca']


    #--------------------------------------------------------
    # test_edit_ca_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_ca_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-ca/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "display_name": "My CA", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "location": "ibmcloud", "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"ca": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        display_name = 'My CA'
        api_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:7054'
        operations_url = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        ca_name = 'ca'
        location = 'ibmcloud'
        tags = ['fabric-ca']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.edit_ca(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for ca_action
#-----------------------------------------------------------------------------
class TestCaAction():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # ca_action()
    #--------------------------------------------------------
    @responses.activate
    def test_ca_action_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-ca/testString/actions')
        mock_response = '{"message": "accepted", "id": "myca", "actions": ["restart"]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=202)

        # Construct a dict representation of a ActionRenew model
        action_renew_model = {}
        action_renew_model['tls_cert'] = True

        # Set up parameter values
        id = 'testString'
        restart = True
        renew = action_renew_model

        # Invoke method
        response = service.ca_action(
            id,
            restart=restart,
            renew=renew,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 202
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['restart'] == True
        assert req_body['renew'] == action_renew_model


    #--------------------------------------------------------
    # test_ca_action_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_ca_action_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-ca/testString/actions')
        mock_response = '{"message": "accepted", "id": "myca", "actions": ["restart"]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=202)

        # Construct a dict representation of a ActionRenew model
        action_renew_model = {}
        action_renew_model['tls_cert'] = True

        # Set up parameter values
        id = 'testString'
        restart = True
        renew = action_renew_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.ca_action(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for create_peer
#-----------------------------------------------------------------------------
class TestCreatePeer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # create_peer()
    #--------------------------------------------------------
    @responses.activate
    def test_create_peer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-peer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a CryptoObjectEnrollmentCa model
        crypto_object_enrollment_ca_model = {}
        crypto_object_enrollment_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model['port'] = 7054
        crypto_object_enrollment_ca_model['name'] = 'ca'
        crypto_object_enrollment_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a CryptoObjectEnrollmentTlsca model
        crypto_object_enrollment_tlsca_model = {}
        crypto_object_enrollment_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model['port'] = 7054
        crypto_object_enrollment_tlsca_model['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a MspCryptoCa model
        msp_crypto_ca_model = {}
        msp_crypto_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a MspCryptoComp model
        msp_crypto_comp_model = {}
        msp_crypto_comp_model['ekey'] = 'testString'
        msp_crypto_comp_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model['tls_key'] = 'testString'
        msp_crypto_comp_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['client_auth'] = client_auth_model

        # Construct a dict representation of a CryptoObjectEnrollment model
        crypto_object_enrollment_model = {}
        crypto_object_enrollment_model['component'] = crypto_enrollment_component_model
        crypto_object_enrollment_model['ca'] = crypto_object_enrollment_ca_model
        crypto_object_enrollment_model['tlsca'] = crypto_object_enrollment_tlsca_model

        # Construct a dict representation of a CryptoObjectMsp model
        crypto_object_msp_model = {}
        crypto_object_msp_model['component'] = msp_crypto_comp_model
        crypto_object_msp_model['ca'] = msp_crypto_ca_model
        crypto_object_msp_model['tlsca'] = msp_crypto_ca_model

        # Construct a dict representation of a CryptoObject model
        crypto_object_model = {}
        crypto_object_model['enrollment'] = crypto_object_enrollment_model
        crypto_object_model['msp'] = crypto_object_msp_model

        # Construct a dict representation of a ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy model
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {}
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a ConfigPeerDeliveryclientAddressOverridesItem model
        config_peer_deliveryclient_address_overrides_item_model = {}
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        # Construct a dict representation of a ConfigPeerGossipElection model
        config_peer_gossip_election_model = {}
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        # Construct a dict representation of a ConfigPeerGossipPvtData model
        config_peer_gossip_pvt_data_model = {}
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        # Construct a dict representation of a ConfigPeerGossipState model
        config_peer_gossip_state_model = {}
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        # Construct a dict representation of a ConfigPeerKeepaliveClient model
        config_peer_keepalive_client_model = {}
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerKeepaliveDeliveryClient model
        config_peer_keepalive_delivery_client_model = {}
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerLimitsConcurrency model
        config_peer_limits_concurrency_model = {}
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigPeerAdminService model
        config_peer_admin_service_model = {}
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        # Construct a dict representation of a ConfigPeerAuthentication model
        config_peer_authentication_model = {}
        config_peer_authentication_model['timewindow'] = '15m'

        # Construct a dict representation of a ConfigPeerChaincodeExternalBuildersItem model
        config_peer_chaincode_external_builders_item_model = {}
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        # Construct a dict representation of a ConfigPeerChaincodeGolang model
        config_peer_chaincode_golang_model = {}
        config_peer_chaincode_golang_model['dynamicLink'] = False

        # Construct a dict representation of a ConfigPeerChaincodeLogging model
        config_peer_chaincode_logging_model = {}
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        # Construct a dict representation of a ConfigPeerChaincodeSystem model
        config_peer_chaincode_system_model = {}
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        # Construct a dict representation of a ConfigPeerClient model
        config_peer_client_model = {}
        config_peer_client_model['connTimeout'] = '2s'

        # Construct a dict representation of a ConfigPeerDeliveryclient model
        config_peer_deliveryclient_model = {}
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        # Construct a dict representation of a ConfigPeerDiscovery model
        config_peer_discovery_model = {}
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        # Construct a dict representation of a ConfigPeerGossip model
        config_peer_gossip_model = {}
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        # Construct a dict representation of a ConfigPeerKeepalive model
        config_peer_keepalive_model = {}
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        # Construct a dict representation of a ConfigPeerLimits model
        config_peer_limits_model = {}
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a ConfigPeerChaincode model
        config_peer_chaincode_model = {}
        config_peer_chaincode_model['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model['installTimeout'] = '300s'
        config_peer_chaincode_model['startuptimeout'] = '300s'
        config_peer_chaincode_model['executetimeout'] = '30s'
        config_peer_chaincode_model['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model['logging'] = config_peer_chaincode_logging_model

        # Construct a dict representation of a ConfigPeerCreatePeer model
        config_peer_create_peer_model = {}
        config_peer_create_peer_model['id'] = 'john-doe'
        config_peer_create_peer_model['networkId'] = 'dev'
        config_peer_create_peer_model['keepalive'] = config_peer_keepalive_model
        config_peer_create_peer_model['gossip'] = config_peer_gossip_model
        config_peer_create_peer_model['authentication'] = config_peer_authentication_model
        config_peer_create_peer_model['BCCSP'] = bccsp_model
        config_peer_create_peer_model['client'] = config_peer_client_model
        config_peer_create_peer_model['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_create_peer_model['adminService'] = config_peer_admin_service_model
        config_peer_create_peer_model['validatorPoolSize'] = 8
        config_peer_create_peer_model['discovery'] = config_peer_discovery_model
        config_peer_create_peer_model['limits'] = config_peer_limits_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigPeerCreate model
        config_peer_create_model = {}
        config_peer_create_model['peer'] = config_peer_create_peer_model
        config_peer_create_model['chaincode'] = config_peer_chaincode_model
        config_peer_create_model['metrics'] = metrics_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectCouchDb model
        resource_object_couch_db_model = {}
        resource_object_couch_db_model['requests'] = resource_requests_model
        resource_object_couch_db_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV1 model
        resource_object_fab_v1_model = {}
        resource_object_fab_v1_model['requests'] = resource_requests_model
        resource_object_fab_v1_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV2 model
        resource_object_fab_v2_model = {}
        resource_object_fab_v2_model['requests'] = resource_requests_model
        resource_object_fab_v2_model['limits'] = resource_limits_model

        # Construct a dict representation of a PeerResources model
        peer_resources_model = {}
        peer_resources_model['chaincodelauncher'] = resource_object_fab_v2_model
        peer_resources_model['couchdb'] = resource_object_couch_db_model
        peer_resources_model['statedb'] = resource_object_model
        peer_resources_model['dind'] = resource_object_fab_v1_model
        peer_resources_model['fluentd'] = resource_object_fab_v1_model
        peer_resources_model['peer'] = resource_object_model
        peer_resources_model['proxy'] = resource_object_model

        # Construct a dict representation of a StorageObject model
        storage_object_model = {}
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a dict representation of a CreatePeerBodyStorage model
        create_peer_body_storage_model = {}
        create_peer_body_storage_model['peer'] = storage_object_model
        create_peer_body_storage_model['statedb'] = storage_object_model

        # Construct a dict representation of a Hsm model
        hsm_model = {}
        hsm_model['pkcs11endpoint'] = 'tcp://example.com:666'

        # Set up parameter values
        msp_id = 'Org1'
        display_name = 'My Peer'
        crypto = crypto_object_model
        config_override = config_peer_create_model
        resources = peer_resources_model
        storage = create_peer_body_storage_model
        zone = '-'
        state_db = 'couchdb'
        tags = ['fabric-ca']
        hsm = hsm_model
        region = '-'
        version = '1.4.6-1'

        # Invoke method
        response = service.create_peer(
            msp_id,
            display_name,
            crypto,
            config_override=config_override,
            resources=resources,
            storage=storage,
            zone=zone,
            state_db=state_db,
            tags=tags,
            hsm=hsm,
            region=region,
            version=version,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['msp_id'] == 'Org1'
        assert req_body['display_name'] == 'My Peer'
        assert req_body['crypto'] == crypto_object_model
        assert req_body['config_override'] == config_peer_create_model
        assert req_body['resources'] == peer_resources_model
        assert req_body['storage'] == create_peer_body_storage_model
        assert req_body['zone'] == '-'
        assert req_body['state_db'] == 'couchdb'
        assert req_body['tags'] == ['fabric-ca']
        assert req_body['hsm'] == hsm_model
        assert req_body['region'] == '-'
        assert req_body['version'] == '1.4.6-1'


    #--------------------------------------------------------
    # test_create_peer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_create_peer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-peer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a CryptoObjectEnrollmentCa model
        crypto_object_enrollment_ca_model = {}
        crypto_object_enrollment_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model['port'] = 7054
        crypto_object_enrollment_ca_model['name'] = 'ca'
        crypto_object_enrollment_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a CryptoObjectEnrollmentTlsca model
        crypto_object_enrollment_tlsca_model = {}
        crypto_object_enrollment_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model['port'] = 7054
        crypto_object_enrollment_tlsca_model['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a MspCryptoCa model
        msp_crypto_ca_model = {}
        msp_crypto_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a MspCryptoComp model
        msp_crypto_comp_model = {}
        msp_crypto_comp_model['ekey'] = 'testString'
        msp_crypto_comp_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model['tls_key'] = 'testString'
        msp_crypto_comp_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['client_auth'] = client_auth_model

        # Construct a dict representation of a CryptoObjectEnrollment model
        crypto_object_enrollment_model = {}
        crypto_object_enrollment_model['component'] = crypto_enrollment_component_model
        crypto_object_enrollment_model['ca'] = crypto_object_enrollment_ca_model
        crypto_object_enrollment_model['tlsca'] = crypto_object_enrollment_tlsca_model

        # Construct a dict representation of a CryptoObjectMsp model
        crypto_object_msp_model = {}
        crypto_object_msp_model['component'] = msp_crypto_comp_model
        crypto_object_msp_model['ca'] = msp_crypto_ca_model
        crypto_object_msp_model['tlsca'] = msp_crypto_ca_model

        # Construct a dict representation of a CryptoObject model
        crypto_object_model = {}
        crypto_object_model['enrollment'] = crypto_object_enrollment_model
        crypto_object_model['msp'] = crypto_object_msp_model

        # Construct a dict representation of a ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy model
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {}
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a ConfigPeerDeliveryclientAddressOverridesItem model
        config_peer_deliveryclient_address_overrides_item_model = {}
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        # Construct a dict representation of a ConfigPeerGossipElection model
        config_peer_gossip_election_model = {}
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        # Construct a dict representation of a ConfigPeerGossipPvtData model
        config_peer_gossip_pvt_data_model = {}
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        # Construct a dict representation of a ConfigPeerGossipState model
        config_peer_gossip_state_model = {}
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        # Construct a dict representation of a ConfigPeerKeepaliveClient model
        config_peer_keepalive_client_model = {}
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerKeepaliveDeliveryClient model
        config_peer_keepalive_delivery_client_model = {}
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerLimitsConcurrency model
        config_peer_limits_concurrency_model = {}
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigPeerAdminService model
        config_peer_admin_service_model = {}
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        # Construct a dict representation of a ConfigPeerAuthentication model
        config_peer_authentication_model = {}
        config_peer_authentication_model['timewindow'] = '15m'

        # Construct a dict representation of a ConfigPeerChaincodeExternalBuildersItem model
        config_peer_chaincode_external_builders_item_model = {}
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        # Construct a dict representation of a ConfigPeerChaincodeGolang model
        config_peer_chaincode_golang_model = {}
        config_peer_chaincode_golang_model['dynamicLink'] = False

        # Construct a dict representation of a ConfigPeerChaincodeLogging model
        config_peer_chaincode_logging_model = {}
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        # Construct a dict representation of a ConfigPeerChaincodeSystem model
        config_peer_chaincode_system_model = {}
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        # Construct a dict representation of a ConfigPeerClient model
        config_peer_client_model = {}
        config_peer_client_model['connTimeout'] = '2s'

        # Construct a dict representation of a ConfigPeerDeliveryclient model
        config_peer_deliveryclient_model = {}
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        # Construct a dict representation of a ConfigPeerDiscovery model
        config_peer_discovery_model = {}
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        # Construct a dict representation of a ConfigPeerGossip model
        config_peer_gossip_model = {}
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        # Construct a dict representation of a ConfigPeerKeepalive model
        config_peer_keepalive_model = {}
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        # Construct a dict representation of a ConfigPeerLimits model
        config_peer_limits_model = {}
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a ConfigPeerChaincode model
        config_peer_chaincode_model = {}
        config_peer_chaincode_model['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model['installTimeout'] = '300s'
        config_peer_chaincode_model['startuptimeout'] = '300s'
        config_peer_chaincode_model['executetimeout'] = '30s'
        config_peer_chaincode_model['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model['logging'] = config_peer_chaincode_logging_model

        # Construct a dict representation of a ConfigPeerCreatePeer model
        config_peer_create_peer_model = {}
        config_peer_create_peer_model['id'] = 'john-doe'
        config_peer_create_peer_model['networkId'] = 'dev'
        config_peer_create_peer_model['keepalive'] = config_peer_keepalive_model
        config_peer_create_peer_model['gossip'] = config_peer_gossip_model
        config_peer_create_peer_model['authentication'] = config_peer_authentication_model
        config_peer_create_peer_model['BCCSP'] = bccsp_model
        config_peer_create_peer_model['client'] = config_peer_client_model
        config_peer_create_peer_model['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_create_peer_model['adminService'] = config_peer_admin_service_model
        config_peer_create_peer_model['validatorPoolSize'] = 8
        config_peer_create_peer_model['discovery'] = config_peer_discovery_model
        config_peer_create_peer_model['limits'] = config_peer_limits_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigPeerCreate model
        config_peer_create_model = {}
        config_peer_create_model['peer'] = config_peer_create_peer_model
        config_peer_create_model['chaincode'] = config_peer_chaincode_model
        config_peer_create_model['metrics'] = metrics_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectCouchDb model
        resource_object_couch_db_model = {}
        resource_object_couch_db_model['requests'] = resource_requests_model
        resource_object_couch_db_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV1 model
        resource_object_fab_v1_model = {}
        resource_object_fab_v1_model['requests'] = resource_requests_model
        resource_object_fab_v1_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV2 model
        resource_object_fab_v2_model = {}
        resource_object_fab_v2_model['requests'] = resource_requests_model
        resource_object_fab_v2_model['limits'] = resource_limits_model

        # Construct a dict representation of a PeerResources model
        peer_resources_model = {}
        peer_resources_model['chaincodelauncher'] = resource_object_fab_v2_model
        peer_resources_model['couchdb'] = resource_object_couch_db_model
        peer_resources_model['statedb'] = resource_object_model
        peer_resources_model['dind'] = resource_object_fab_v1_model
        peer_resources_model['fluentd'] = resource_object_fab_v1_model
        peer_resources_model['peer'] = resource_object_model
        peer_resources_model['proxy'] = resource_object_model

        # Construct a dict representation of a StorageObject model
        storage_object_model = {}
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a dict representation of a CreatePeerBodyStorage model
        create_peer_body_storage_model = {}
        create_peer_body_storage_model['peer'] = storage_object_model
        create_peer_body_storage_model['statedb'] = storage_object_model

        # Construct a dict representation of a Hsm model
        hsm_model = {}
        hsm_model['pkcs11endpoint'] = 'tcp://example.com:666'

        # Set up parameter values
        msp_id = 'Org1'
        display_name = 'My Peer'
        crypto = crypto_object_model
        config_override = config_peer_create_model
        resources = peer_resources_model
        storage = create_peer_body_storage_model
        zone = '-'
        state_db = 'couchdb'
        tags = ['fabric-ca']
        hsm = hsm_model
        region = '-'
        version = '1.4.6-1'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "msp_id": msp_id,
            "display_name": display_name,
            "crypto": crypto,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.create_peer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for import_peer
#-----------------------------------------------------------------------------
class TestImportPeer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # import_peer()
    #--------------------------------------------------------
    @responses.activate
    def test_import_peer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-peer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a MspCryptoFieldCa model
        msp_crypto_field_ca_model = {}
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldComponent model
        msp_crypto_field_component_model = {}
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldTlsca model
        msp_crypto_field_tlsca_model = {}
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoField model
        msp_crypto_field_model = {}
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        # Set up parameter values
        display_name = 'My Peer'
        grpcwp_url = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        msp = msp_crypto_field_model
        msp_id = 'Org1'
        api_url = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        location = 'ibmcloud'
        operations_url = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        tags = ['fabric-ca']

        # Invoke method
        response = service.import_peer(
            display_name,
            grpcwp_url,
            msp,
            msp_id,
            api_url=api_url,
            location=location,
            operations_url=operations_url,
            tags=tags,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['display_name'] == 'My Peer'
        assert req_body['grpcwp_url'] == 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        assert req_body['msp'] == msp_crypto_field_model
        assert req_body['msp_id'] == 'Org1'
        assert req_body['api_url'] == 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        assert req_body['location'] == 'ibmcloud'
        assert req_body['operations_url'] == 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        assert req_body['tags'] == ['fabric-ca']


    #--------------------------------------------------------
    # test_import_peer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_import_peer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-peer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a MspCryptoFieldCa model
        msp_crypto_field_ca_model = {}
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldComponent model
        msp_crypto_field_component_model = {}
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldTlsca model
        msp_crypto_field_tlsca_model = {}
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoField model
        msp_crypto_field_model = {}
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        # Set up parameter values
        display_name = 'My Peer'
        grpcwp_url = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        msp = msp_crypto_field_model
        msp_id = 'Org1'
        api_url = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        location = 'ibmcloud'
        operations_url = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        tags = ['fabric-ca']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "display_name": display_name,
            "grpcwp_url": grpcwp_url,
            "msp": msp,
            "msp_id": msp_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.import_peer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for edit_peer
#-----------------------------------------------------------------------------
class TestEditPeer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # edit_peer()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_peer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-peer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        display_name = 'My Peer'
        api_url = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        operations_url = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        grpcwp_url = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        msp_id = 'Org1'
        location = 'ibmcloud'
        tags = ['fabric-ca']

        # Invoke method
        response = service.edit_peer(
            id,
            display_name=display_name,
            api_url=api_url,
            operations_url=operations_url,
            grpcwp_url=grpcwp_url,
            msp_id=msp_id,
            location=location,
            tags=tags,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['display_name'] == 'My Peer'
        assert req_body['api_url'] == 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        assert req_body['operations_url'] == 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        assert req_body['grpcwp_url'] == 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        assert req_body['msp_id'] == 'Org1'
        assert req_body['location'] == 'ibmcloud'
        assert req_body['tags'] == ['fabric-ca']


    #--------------------------------------------------------
    # test_edit_peer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_peer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-peer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        display_name = 'My Peer'
        api_url = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        operations_url = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        grpcwp_url = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        msp_id = 'Org1'
        location = 'ibmcloud'
        tags = ['fabric-ca']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.edit_peer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for peer_action
#-----------------------------------------------------------------------------
class TestPeerAction():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # peer_action()
    #--------------------------------------------------------
    @responses.activate
    def test_peer_action_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-peer/testString/actions')
        mock_response = '{"message": "accepted", "id": "myca", "actions": ["restart"]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=202)

        # Construct a dict representation of a ActionReenroll model
        action_reenroll_model = {}
        action_reenroll_model['tls_cert'] = True
        action_reenroll_model['ecert'] = True

        # Construct a dict representation of a ActionEnroll model
        action_enroll_model = {}
        action_enroll_model['tls_cert'] = True
        action_enroll_model['ecert'] = True

        # Set up parameter values
        id = 'testString'
        restart = True
        reenroll = action_reenroll_model
        enroll = action_enroll_model
        upgrade_dbs = True

        # Invoke method
        response = service.peer_action(
            id,
            restart=restart,
            reenroll=reenroll,
            enroll=enroll,
            upgrade_dbs=upgrade_dbs,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 202
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['restart'] == True
        assert req_body['reenroll'] == action_reenroll_model
        assert req_body['enroll'] == action_enroll_model
        assert req_body['upgrade_dbs'] == True


    #--------------------------------------------------------
    # test_peer_action_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_peer_action_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-peer/testString/actions')
        mock_response = '{"message": "accepted", "id": "myca", "actions": ["restart"]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=202)

        # Construct a dict representation of a ActionReenroll model
        action_reenroll_model = {}
        action_reenroll_model['tls_cert'] = True
        action_reenroll_model['ecert'] = True

        # Construct a dict representation of a ActionEnroll model
        action_enroll_model = {}
        action_enroll_model['tls_cert'] = True
        action_enroll_model['ecert'] = True

        # Set up parameter values
        id = 'testString'
        restart = True
        reenroll = action_reenroll_model
        enroll = action_enroll_model
        upgrade_dbs = True

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.peer_action(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for update_peer
#-----------------------------------------------------------------------------
class TestUpdatePeer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # update_peer()
    #--------------------------------------------------------
    @responses.activate
    def test_update_peer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-peer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy model
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {}
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        # Construct a dict representation of a ConfigPeerDeliveryclientAddressOverridesItem model
        config_peer_deliveryclient_address_overrides_item_model = {}
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        # Construct a dict representation of a ConfigPeerGossipElection model
        config_peer_gossip_election_model = {}
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        # Construct a dict representation of a ConfigPeerGossipPvtData model
        config_peer_gossip_pvt_data_model = {}
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        # Construct a dict representation of a ConfigPeerGossipState model
        config_peer_gossip_state_model = {}
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        # Construct a dict representation of a ConfigPeerKeepaliveClient model
        config_peer_keepalive_client_model = {}
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerKeepaliveDeliveryClient model
        config_peer_keepalive_delivery_client_model = {}
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerLimitsConcurrency model
        config_peer_limits_concurrency_model = {}
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        # Construct a dict representation of a ConfigPeerAdminService model
        config_peer_admin_service_model = {}
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        # Construct a dict representation of a ConfigPeerAuthentication model
        config_peer_authentication_model = {}
        config_peer_authentication_model['timewindow'] = '15m'

        # Construct a dict representation of a ConfigPeerChaincodeExternalBuildersItem model
        config_peer_chaincode_external_builders_item_model = {}
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        # Construct a dict representation of a ConfigPeerChaincodeGolang model
        config_peer_chaincode_golang_model = {}
        config_peer_chaincode_golang_model['dynamicLink'] = False

        # Construct a dict representation of a ConfigPeerChaincodeLogging model
        config_peer_chaincode_logging_model = {}
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        # Construct a dict representation of a ConfigPeerChaincodeSystem model
        config_peer_chaincode_system_model = {}
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        # Construct a dict representation of a ConfigPeerClient model
        config_peer_client_model = {}
        config_peer_client_model['connTimeout'] = '2s'

        # Construct a dict representation of a ConfigPeerDeliveryclient model
        config_peer_deliveryclient_model = {}
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        # Construct a dict representation of a ConfigPeerDiscovery model
        config_peer_discovery_model = {}
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        # Construct a dict representation of a ConfigPeerGossip model
        config_peer_gossip_model = {}
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        # Construct a dict representation of a ConfigPeerKeepalive model
        config_peer_keepalive_model = {}
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        # Construct a dict representation of a ConfigPeerLimits model
        config_peer_limits_model = {}
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a ConfigPeerChaincode model
        config_peer_chaincode_model = {}
        config_peer_chaincode_model['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model['installTimeout'] = '300s'
        config_peer_chaincode_model['startuptimeout'] = '300s'
        config_peer_chaincode_model['executetimeout'] = '30s'
        config_peer_chaincode_model['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model['logging'] = config_peer_chaincode_logging_model

        # Construct a dict representation of a ConfigPeerUpdatePeer model
        config_peer_update_peer_model = {}
        config_peer_update_peer_model['id'] = 'john-doe'
        config_peer_update_peer_model['networkId'] = 'dev'
        config_peer_update_peer_model['keepalive'] = config_peer_keepalive_model
        config_peer_update_peer_model['gossip'] = config_peer_gossip_model
        config_peer_update_peer_model['authentication'] = config_peer_authentication_model
        config_peer_update_peer_model['client'] = config_peer_client_model
        config_peer_update_peer_model['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_update_peer_model['adminService'] = config_peer_admin_service_model
        config_peer_update_peer_model['validatorPoolSize'] = 8
        config_peer_update_peer_model['discovery'] = config_peer_discovery_model
        config_peer_update_peer_model['limits'] = config_peer_limits_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigPeerUpdate model
        config_peer_update_model = {}
        config_peer_update_model['peer'] = config_peer_update_peer_model
        config_peer_update_model['chaincode'] = config_peer_chaincode_model
        config_peer_update_model['metrics'] = metrics_model

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldCa model
        update_enrollment_crypto_field_ca_model = {}
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldTlsca model
        update_enrollment_crypto_field_tlsca_model = {}
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldCa model
        update_msp_crypto_field_ca_model = {}
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldComponent model
        update_msp_crypto_field_component_model = {}
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        # Construct a dict representation of a UpdateMspCryptoFieldTlsca model
        update_msp_crypto_field_tlsca_model = {}
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateEnrollmentCryptoField model
        update_enrollment_crypto_field_model = {}
        update_enrollment_crypto_field_model['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model['tlsca'] = update_enrollment_crypto_field_tlsca_model

        # Construct a dict representation of a UpdateMspCryptoField model
        update_msp_crypto_field_model = {}
        update_msp_crypto_field_model['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model['component'] = update_msp_crypto_field_component_model

        # Construct a dict representation of a UpdatePeerBodyCrypto model
        update_peer_body_crypto_model = {}
        update_peer_body_crypto_model['enrollment'] = update_enrollment_crypto_field_model
        update_peer_body_crypto_model['msp'] = update_msp_crypto_field_model

        # Construct a dict representation of a NodeOu model
        node_ou_model = {}
        node_ou_model['enabled'] = True

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectCouchDb model
        resource_object_couch_db_model = {}
        resource_object_couch_db_model['requests'] = resource_requests_model
        resource_object_couch_db_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV1 model
        resource_object_fab_v1_model = {}
        resource_object_fab_v1_model['requests'] = resource_requests_model
        resource_object_fab_v1_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV2 model
        resource_object_fab_v2_model = {}
        resource_object_fab_v2_model['requests'] = resource_requests_model
        resource_object_fab_v2_model['limits'] = resource_limits_model

        # Construct a dict representation of a PeerResources model
        peer_resources_model = {}
        peer_resources_model['chaincodelauncher'] = resource_object_fab_v2_model
        peer_resources_model['couchdb'] = resource_object_couch_db_model
        peer_resources_model['statedb'] = resource_object_model
        peer_resources_model['dind'] = resource_object_fab_v1_model
        peer_resources_model['fluentd'] = resource_object_fab_v1_model
        peer_resources_model['peer'] = resource_object_model
        peer_resources_model['proxy'] = resource_object_model

        # Set up parameter values
        id = 'testString'
        admin_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        config_override = config_peer_update_model
        crypto = update_peer_body_crypto_model
        node_ou = node_ou_model
        replicas = 1
        resources = peer_resources_model
        version = '1.4.6-1'
        zone = '-'

        # Invoke method
        response = service.update_peer(
            id,
            admin_certs=admin_certs,
            config_override=config_override,
            crypto=crypto,
            node_ou=node_ou,
            replicas=replicas,
            resources=resources,
            version=version,
            zone=zone,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['admin_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['config_override'] == config_peer_update_model
        assert req_body['crypto'] == update_peer_body_crypto_model
        assert req_body['node_ou'] == node_ou_model
        assert req_body['replicas'] == 1
        assert req_body['resources'] == peer_resources_model
        assert req_body['version'] == '1.4.6-1'
        assert req_body['zone'] == '-'


    #--------------------------------------------------------
    # test_update_peer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_update_peer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-peer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "display_name": "My Peer", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "location": "ibmcloud", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "config_override": {"anyKey": "anyValue"}, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"peer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy model
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {}
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        # Construct a dict representation of a ConfigPeerDeliveryclientAddressOverridesItem model
        config_peer_deliveryclient_address_overrides_item_model = {}
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        # Construct a dict representation of a ConfigPeerGossipElection model
        config_peer_gossip_election_model = {}
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        # Construct a dict representation of a ConfigPeerGossipPvtData model
        config_peer_gossip_pvt_data_model = {}
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        # Construct a dict representation of a ConfigPeerGossipState model
        config_peer_gossip_state_model = {}
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        # Construct a dict representation of a ConfigPeerKeepaliveClient model
        config_peer_keepalive_client_model = {}
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerKeepaliveDeliveryClient model
        config_peer_keepalive_delivery_client_model = {}
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        # Construct a dict representation of a ConfigPeerLimitsConcurrency model
        config_peer_limits_concurrency_model = {}
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        # Construct a dict representation of a ConfigPeerAdminService model
        config_peer_admin_service_model = {}
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        # Construct a dict representation of a ConfigPeerAuthentication model
        config_peer_authentication_model = {}
        config_peer_authentication_model['timewindow'] = '15m'

        # Construct a dict representation of a ConfigPeerChaincodeExternalBuildersItem model
        config_peer_chaincode_external_builders_item_model = {}
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        # Construct a dict representation of a ConfigPeerChaincodeGolang model
        config_peer_chaincode_golang_model = {}
        config_peer_chaincode_golang_model['dynamicLink'] = False

        # Construct a dict representation of a ConfigPeerChaincodeLogging model
        config_peer_chaincode_logging_model = {}
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        # Construct a dict representation of a ConfigPeerChaincodeSystem model
        config_peer_chaincode_system_model = {}
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        # Construct a dict representation of a ConfigPeerClient model
        config_peer_client_model = {}
        config_peer_client_model['connTimeout'] = '2s'

        # Construct a dict representation of a ConfigPeerDeliveryclient model
        config_peer_deliveryclient_model = {}
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        # Construct a dict representation of a ConfigPeerDiscovery model
        config_peer_discovery_model = {}
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        # Construct a dict representation of a ConfigPeerGossip model
        config_peer_gossip_model = {}
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        # Construct a dict representation of a ConfigPeerKeepalive model
        config_peer_keepalive_model = {}
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        # Construct a dict representation of a ConfigPeerLimits model
        config_peer_limits_model = {}
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        # Construct a dict representation of a MetricsStatsd model
        metrics_statsd_model = {}
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a dict representation of a ConfigPeerChaincode model
        config_peer_chaincode_model = {}
        config_peer_chaincode_model['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model['installTimeout'] = '300s'
        config_peer_chaincode_model['startuptimeout'] = '300s'
        config_peer_chaincode_model['executetimeout'] = '30s'
        config_peer_chaincode_model['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model['logging'] = config_peer_chaincode_logging_model

        # Construct a dict representation of a ConfigPeerUpdatePeer model
        config_peer_update_peer_model = {}
        config_peer_update_peer_model['id'] = 'john-doe'
        config_peer_update_peer_model['networkId'] = 'dev'
        config_peer_update_peer_model['keepalive'] = config_peer_keepalive_model
        config_peer_update_peer_model['gossip'] = config_peer_gossip_model
        config_peer_update_peer_model['authentication'] = config_peer_authentication_model
        config_peer_update_peer_model['client'] = config_peer_client_model
        config_peer_update_peer_model['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_update_peer_model['adminService'] = config_peer_admin_service_model
        config_peer_update_peer_model['validatorPoolSize'] = 8
        config_peer_update_peer_model['discovery'] = config_peer_discovery_model
        config_peer_update_peer_model['limits'] = config_peer_limits_model

        # Construct a dict representation of a Metrics model
        metrics_model = {}
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a dict representation of a ConfigPeerUpdate model
        config_peer_update_model = {}
        config_peer_update_model['peer'] = config_peer_update_peer_model
        config_peer_update_model['chaincode'] = config_peer_chaincode_model
        config_peer_update_model['metrics'] = metrics_model

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldCa model
        update_enrollment_crypto_field_ca_model = {}
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldTlsca model
        update_enrollment_crypto_field_tlsca_model = {}
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldCa model
        update_msp_crypto_field_ca_model = {}
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldComponent model
        update_msp_crypto_field_component_model = {}
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        # Construct a dict representation of a UpdateMspCryptoFieldTlsca model
        update_msp_crypto_field_tlsca_model = {}
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateEnrollmentCryptoField model
        update_enrollment_crypto_field_model = {}
        update_enrollment_crypto_field_model['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model['tlsca'] = update_enrollment_crypto_field_tlsca_model

        # Construct a dict representation of a UpdateMspCryptoField model
        update_msp_crypto_field_model = {}
        update_msp_crypto_field_model['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model['component'] = update_msp_crypto_field_component_model

        # Construct a dict representation of a UpdatePeerBodyCrypto model
        update_peer_body_crypto_model = {}
        update_peer_body_crypto_model['enrollment'] = update_enrollment_crypto_field_model
        update_peer_body_crypto_model['msp'] = update_msp_crypto_field_model

        # Construct a dict representation of a NodeOu model
        node_ou_model = {}
        node_ou_model['enabled'] = True

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectCouchDb model
        resource_object_couch_db_model = {}
        resource_object_couch_db_model['requests'] = resource_requests_model
        resource_object_couch_db_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV1 model
        resource_object_fab_v1_model = {}
        resource_object_fab_v1_model['requests'] = resource_requests_model
        resource_object_fab_v1_model['limits'] = resource_limits_model

        # Construct a dict representation of a ResourceObjectFabV2 model
        resource_object_fab_v2_model = {}
        resource_object_fab_v2_model['requests'] = resource_requests_model
        resource_object_fab_v2_model['limits'] = resource_limits_model

        # Construct a dict representation of a PeerResources model
        peer_resources_model = {}
        peer_resources_model['chaincodelauncher'] = resource_object_fab_v2_model
        peer_resources_model['couchdb'] = resource_object_couch_db_model
        peer_resources_model['statedb'] = resource_object_model
        peer_resources_model['dind'] = resource_object_fab_v1_model
        peer_resources_model['fluentd'] = resource_object_fab_v1_model
        peer_resources_model['peer'] = resource_object_model
        peer_resources_model['proxy'] = resource_object_model

        # Set up parameter values
        id = 'testString'
        admin_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        config_override = config_peer_update_model
        crypto = update_peer_body_crypto_model
        node_ou = node_ou_model
        replicas = 1
        resources = peer_resources_model
        version = '1.4.6-1'
        zone = '-'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.update_peer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for create_orderer
#-----------------------------------------------------------------------------
class TestCreateOrderer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # create_orderer()
    #--------------------------------------------------------
    @responses.activate
    def test_create_orderer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-orderer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a CryptoObjectEnrollmentCa model
        crypto_object_enrollment_ca_model = {}
        crypto_object_enrollment_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model['port'] = 7054
        crypto_object_enrollment_ca_model['name'] = 'ca'
        crypto_object_enrollment_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a CryptoObjectEnrollmentTlsca model
        crypto_object_enrollment_tlsca_model = {}
        crypto_object_enrollment_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model['port'] = 7054
        crypto_object_enrollment_tlsca_model['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a MspCryptoCa model
        msp_crypto_ca_model = {}
        msp_crypto_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a MspCryptoComp model
        msp_crypto_comp_model = {}
        msp_crypto_comp_model['ekey'] = 'testString'
        msp_crypto_comp_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model['tls_key'] = 'testString'
        msp_crypto_comp_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['client_auth'] = client_auth_model

        # Construct a dict representation of a CryptoObjectEnrollment model
        crypto_object_enrollment_model = {}
        crypto_object_enrollment_model['component'] = crypto_enrollment_component_model
        crypto_object_enrollment_model['ca'] = crypto_object_enrollment_ca_model
        crypto_object_enrollment_model['tlsca'] = crypto_object_enrollment_tlsca_model

        # Construct a dict representation of a CryptoObjectMsp model
        crypto_object_msp_model = {}
        crypto_object_msp_model['component'] = msp_crypto_comp_model
        crypto_object_msp_model['ca'] = msp_crypto_ca_model
        crypto_object_msp_model['tlsca'] = msp_crypto_ca_model

        # Construct a dict representation of a CryptoObject model
        crypto_object_model = {}
        crypto_object_model['enrollment'] = crypto_object_enrollment_model
        crypto_object_model['msp'] = crypto_object_msp_model

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigOrdererAuthentication model
        config_orderer_authentication_model = {}
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        # Construct a dict representation of a ConfigOrdererKeepalive model
        config_orderer_keepalive_model = {}
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        # Construct a dict representation of a ConfigOrdererMetricsStatsd model
        config_orderer_metrics_statsd_model = {}
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        # Construct a dict representation of a ConfigOrdererDebug model
        config_orderer_debug_model = {}
        config_orderer_debug_model['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model['DeliverTraceDir'] = 'testString'

        # Construct a dict representation of a ConfigOrdererGeneral model
        config_orderer_general_model = {}
        config_orderer_general_model['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_model['BCCSP'] = bccsp_model
        config_orderer_general_model['Authentication'] = config_orderer_authentication_model

        # Construct a dict representation of a ConfigOrdererMetrics model
        config_orderer_metrics_model = {}
        config_orderer_metrics_model['Provider'] = 'disabled'
        config_orderer_metrics_model['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a dict representation of a ConfigOrdererCreate model
        config_orderer_create_model = {}
        config_orderer_create_model['General'] = config_orderer_general_model
        config_orderer_create_model['Debug'] = config_orderer_debug_model
        config_orderer_create_model['Metrics'] = config_orderer_metrics_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a CreateOrdererRaftBodyResources model
        create_orderer_raft_body_resources_model = {}
        create_orderer_raft_body_resources_model['orderer'] = resource_object_model
        create_orderer_raft_body_resources_model['proxy'] = resource_object_model

        # Construct a dict representation of a StorageObject model
        storage_object_model = {}
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a dict representation of a CreateOrdererRaftBodyStorage model
        create_orderer_raft_body_storage_model = {}
        create_orderer_raft_body_storage_model['orderer'] = storage_object_model

        # Construct a dict representation of a Hsm model
        hsm_model = {}
        hsm_model['pkcs11endpoint'] = 'tcp://example.com:666'

        # Set up parameter values
        orderer_type = 'raft'
        msp_id = 'Org1'
        display_name = 'orderer'
        crypto = [crypto_object_model]
        cluster_name = 'ordering service 1'
        cluster_id = 'abcde'
        external_append = 'false'
        config_override = [config_orderer_create_model]
        resources = create_orderer_raft_body_resources_model
        storage = create_orderer_raft_body_storage_model
        system_channel_id = 'testchainid'
        zone = ['-']
        tags = ['fabric-ca']
        region = ['-']
        hsm = hsm_model
        version = '1.4.6-1'

        # Invoke method
        response = service.create_orderer(
            orderer_type,
            msp_id,
            display_name,
            crypto,
            cluster_name=cluster_name,
            cluster_id=cluster_id,
            external_append=external_append,
            config_override=config_override,
            resources=resources,
            storage=storage,
            system_channel_id=system_channel_id,
            zone=zone,
            tags=tags,
            region=region,
            hsm=hsm,
            version=version,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['orderer_type'] == 'raft'
        assert req_body['msp_id'] == 'Org1'
        assert req_body['display_name'] == 'orderer'
        assert req_body['crypto'] == [crypto_object_model]
        assert req_body['cluster_name'] == 'ordering service 1'
        assert req_body['cluster_id'] == 'abcde'
        assert req_body['external_append'] == 'false'
        assert req_body['config_override'] == [config_orderer_create_model]
        assert req_body['resources'] == create_orderer_raft_body_resources_model
        assert req_body['storage'] == create_orderer_raft_body_storage_model
        assert req_body['system_channel_id'] == 'testchainid'
        assert req_body['zone'] == ['-']
        assert req_body['tags'] == ['fabric-ca']
        assert req_body['region'] == ['-']
        assert req_body['hsm'] == hsm_model
        assert req_body['version'] == '1.4.6-1'


    #--------------------------------------------------------
    # test_create_orderer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_create_orderer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-orderer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a CryptoObjectEnrollmentCa model
        crypto_object_enrollment_ca_model = {}
        crypto_object_enrollment_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model['port'] = 7054
        crypto_object_enrollment_ca_model['name'] = 'ca'
        crypto_object_enrollment_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a CryptoObjectEnrollmentTlsca model
        crypto_object_enrollment_tlsca_model = {}
        crypto_object_enrollment_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model['port'] = 7054
        crypto_object_enrollment_tlsca_model['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a MspCryptoCa model
        msp_crypto_ca_model = {}
        msp_crypto_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a MspCryptoComp model
        msp_crypto_comp_model = {}
        msp_crypto_comp_model['ekey'] = 'testString'
        msp_crypto_comp_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model['tls_key'] = 'testString'
        msp_crypto_comp_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['client_auth'] = client_auth_model

        # Construct a dict representation of a CryptoObjectEnrollment model
        crypto_object_enrollment_model = {}
        crypto_object_enrollment_model['component'] = crypto_enrollment_component_model
        crypto_object_enrollment_model['ca'] = crypto_object_enrollment_ca_model
        crypto_object_enrollment_model['tlsca'] = crypto_object_enrollment_tlsca_model

        # Construct a dict representation of a CryptoObjectMsp model
        crypto_object_msp_model = {}
        crypto_object_msp_model['component'] = msp_crypto_comp_model
        crypto_object_msp_model['ca'] = msp_crypto_ca_model
        crypto_object_msp_model['tlsca'] = msp_crypto_ca_model

        # Construct a dict representation of a CryptoObject model
        crypto_object_model = {}
        crypto_object_model['enrollment'] = crypto_object_enrollment_model
        crypto_object_model['msp'] = crypto_object_msp_model

        # Construct a dict representation of a BccspPKCS11 model
        bccsp_pkc_s11_model = {}
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        # Construct a dict representation of a BccspSW model
        bccsp_sw_model = {}
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a dict representation of a Bccsp model
        bccsp_model = {}
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        # Construct a dict representation of a ConfigOrdererAuthentication model
        config_orderer_authentication_model = {}
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        # Construct a dict representation of a ConfigOrdererKeepalive model
        config_orderer_keepalive_model = {}
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        # Construct a dict representation of a ConfigOrdererMetricsStatsd model
        config_orderer_metrics_statsd_model = {}
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        # Construct a dict representation of a ConfigOrdererDebug model
        config_orderer_debug_model = {}
        config_orderer_debug_model['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model['DeliverTraceDir'] = 'testString'

        # Construct a dict representation of a ConfigOrdererGeneral model
        config_orderer_general_model = {}
        config_orderer_general_model['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_model['BCCSP'] = bccsp_model
        config_orderer_general_model['Authentication'] = config_orderer_authentication_model

        # Construct a dict representation of a ConfigOrdererMetrics model
        config_orderer_metrics_model = {}
        config_orderer_metrics_model['Provider'] = 'disabled'
        config_orderer_metrics_model['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a dict representation of a ConfigOrdererCreate model
        config_orderer_create_model = {}
        config_orderer_create_model['General'] = config_orderer_general_model
        config_orderer_create_model['Debug'] = config_orderer_debug_model
        config_orderer_create_model['Metrics'] = config_orderer_metrics_model

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a CreateOrdererRaftBodyResources model
        create_orderer_raft_body_resources_model = {}
        create_orderer_raft_body_resources_model['orderer'] = resource_object_model
        create_orderer_raft_body_resources_model['proxy'] = resource_object_model

        # Construct a dict representation of a StorageObject model
        storage_object_model = {}
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a dict representation of a CreateOrdererRaftBodyStorage model
        create_orderer_raft_body_storage_model = {}
        create_orderer_raft_body_storage_model['orderer'] = storage_object_model

        # Construct a dict representation of a Hsm model
        hsm_model = {}
        hsm_model['pkcs11endpoint'] = 'tcp://example.com:666'

        # Set up parameter values
        orderer_type = 'raft'
        msp_id = 'Org1'
        display_name = 'orderer'
        crypto = [crypto_object_model]
        cluster_name = 'ordering service 1'
        cluster_id = 'abcde'
        external_append = 'false'
        config_override = [config_orderer_create_model]
        resources = create_orderer_raft_body_resources_model
        storage = create_orderer_raft_body_storage_model
        system_channel_id = 'testchainid'
        zone = ['-']
        tags = ['fabric-ca']
        region = ['-']
        hsm = hsm_model
        version = '1.4.6-1'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "orderer_type": orderer_type,
            "msp_id": msp_id,
            "display_name": display_name,
            "crypto": crypto,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.create_orderer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for import_orderer
#-----------------------------------------------------------------------------
class TestImportOrderer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # import_orderer()
    #--------------------------------------------------------
    @responses.activate
    def test_import_orderer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-orderer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a MspCryptoFieldCa model
        msp_crypto_field_ca_model = {}
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldComponent model
        msp_crypto_field_component_model = {}
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldTlsca model
        msp_crypto_field_tlsca_model = {}
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoField model
        msp_crypto_field_model = {}
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        # Set up parameter values
        cluster_name = 'ordering service 1'
        display_name = 'orderer'
        grpcwp_url = 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        msp = msp_crypto_field_model
        msp_id = 'Org1'
        api_url = 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        cluster_id = 'testString'
        location = 'ibmcloud'
        operations_url = 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        system_channel_id = 'testchainid'
        tags = ['fabric-ca']

        # Invoke method
        response = service.import_orderer(
            cluster_name,
            display_name,
            grpcwp_url,
            msp,
            msp_id,
            api_url=api_url,
            cluster_id=cluster_id,
            location=location,
            operations_url=operations_url,
            system_channel_id=system_channel_id,
            tags=tags,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['cluster_name'] == 'ordering service 1'
        assert req_body['display_name'] == 'orderer'
        assert req_body['grpcwp_url'] == 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        assert req_body['msp'] == msp_crypto_field_model
        assert req_body['msp_id'] == 'Org1'
        assert req_body['api_url'] == 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        assert req_body['cluster_id'] == 'testString'
        assert req_body['location'] == 'ibmcloud'
        assert req_body['operations_url'] == 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        assert req_body['system_channel_id'] == 'testchainid'
        assert req_body['tags'] == ['fabric-ca']


    #--------------------------------------------------------
    # test_import_orderer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_import_orderer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-orderer')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a MspCryptoFieldCa model
        msp_crypto_field_ca_model = {}
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldComponent model
        msp_crypto_field_component_model = {}
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoFieldTlsca model
        msp_crypto_field_tlsca_model = {}
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a MspCryptoField model
        msp_crypto_field_model = {}
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        # Set up parameter values
        cluster_name = 'ordering service 1'
        display_name = 'orderer'
        grpcwp_url = 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        msp = msp_crypto_field_model
        msp_id = 'Org1'
        api_url = 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        cluster_id = 'testString'
        location = 'ibmcloud'
        operations_url = 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        system_channel_id = 'testchainid'
        tags = ['fabric-ca']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "cluster_name": cluster_name,
            "display_name": display_name,
            "grpcwp_url": grpcwp_url,
            "msp": msp,
            "msp_id": msp_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.import_orderer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for edit_orderer
#-----------------------------------------------------------------------------
class TestEditOrderer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # edit_orderer()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_orderer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-orderer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        cluster_name = 'ordering service 1'
        display_name = 'orderer'
        api_url = 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        operations_url = 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        grpcwp_url = 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        msp_id = 'Org1'
        consenter_proposal_fin = True
        location = 'ibmcloud'
        system_channel_id = 'testchainid'
        tags = ['fabric-ca']

        # Invoke method
        response = service.edit_orderer(
            id,
            cluster_name=cluster_name,
            display_name=display_name,
            api_url=api_url,
            operations_url=operations_url,
            grpcwp_url=grpcwp_url,
            msp_id=msp_id,
            consenter_proposal_fin=consenter_proposal_fin,
            location=location,
            system_channel_id=system_channel_id,
            tags=tags,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['cluster_name'] == 'ordering service 1'
        assert req_body['display_name'] == 'orderer'
        assert req_body['api_url'] == 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        assert req_body['operations_url'] == 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        assert req_body['grpcwp_url'] == 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        assert req_body['msp_id'] == 'Org1'
        assert req_body['consenter_proposal_fin'] == True
        assert req_body['location'] == 'ibmcloud'
        assert req_body['system_channel_id'] == 'testchainid'
        assert req_body['tags'] == ['fabric-ca']


    #--------------------------------------------------------
    # test_edit_orderer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_orderer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/fabric-orderer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        cluster_name = 'ordering service 1'
        display_name = 'orderer'
        api_url = 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        operations_url = 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        grpcwp_url = 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        msp_id = 'Org1'
        consenter_proposal_fin = True
        location = 'ibmcloud'
        system_channel_id = 'testchainid'
        tags = ['fabric-ca']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.edit_orderer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for orderer_action
#-----------------------------------------------------------------------------
class TestOrdererAction():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # orderer_action()
    #--------------------------------------------------------
    @responses.activate
    def test_orderer_action_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-orderer/testString/actions')
        mock_response = '{"message": "accepted", "id": "myca", "actions": ["restart"]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=202)

        # Construct a dict representation of a ActionReenroll model
        action_reenroll_model = {}
        action_reenroll_model['tls_cert'] = True
        action_reenroll_model['ecert'] = True

        # Construct a dict representation of a ActionEnroll model
        action_enroll_model = {}
        action_enroll_model['tls_cert'] = True
        action_enroll_model['ecert'] = True

        # Set up parameter values
        id = 'testString'
        restart = True
        reenroll = action_reenroll_model
        enroll = action_enroll_model

        # Invoke method
        response = service.orderer_action(
            id,
            restart=restart,
            reenroll=reenroll,
            enroll=enroll,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 202
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['restart'] == True
        assert req_body['reenroll'] == action_reenroll_model
        assert req_body['enroll'] == action_enroll_model


    #--------------------------------------------------------
    # test_orderer_action_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_orderer_action_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-orderer/testString/actions')
        mock_response = '{"message": "accepted", "id": "myca", "actions": ["restart"]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=202)

        # Construct a dict representation of a ActionReenroll model
        action_reenroll_model = {}
        action_reenroll_model['tls_cert'] = True
        action_reenroll_model['ecert'] = True

        # Construct a dict representation of a ActionEnroll model
        action_enroll_model = {}
        action_enroll_model['tls_cert'] = True
        action_enroll_model['ecert'] = True

        # Set up parameter values
        id = 'testString'
        restart = True
        reenroll = action_reenroll_model
        enroll = action_enroll_model

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.orderer_action(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for update_orderer
#-----------------------------------------------------------------------------
class TestUpdateOrderer():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # update_orderer()
    #--------------------------------------------------------
    @responses.activate
    def test_update_orderer_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-orderer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigOrdererAuthentication model
        config_orderer_authentication_model = {}
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        # Construct a dict representation of a ConfigOrdererKeepalive model
        config_orderer_keepalive_model = {}
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        # Construct a dict representation of a ConfigOrdererMetricsStatsd model
        config_orderer_metrics_statsd_model = {}
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        # Construct a dict representation of a ConfigOrdererDebug model
        config_orderer_debug_model = {}
        config_orderer_debug_model['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model['DeliverTraceDir'] = 'testString'

        # Construct a dict representation of a ConfigOrdererGeneralUpdate model
        config_orderer_general_update_model = {}
        config_orderer_general_update_model['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_update_model['Authentication'] = config_orderer_authentication_model

        # Construct a dict representation of a ConfigOrdererMetrics model
        config_orderer_metrics_model = {}
        config_orderer_metrics_model['Provider'] = 'disabled'
        config_orderer_metrics_model['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a dict representation of a ConfigOrdererUpdate model
        config_orderer_update_model = {}
        config_orderer_update_model['General'] = config_orderer_general_update_model
        config_orderer_update_model['Debug'] = config_orderer_debug_model
        config_orderer_update_model['Metrics'] = config_orderer_metrics_model

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldCa model
        update_enrollment_crypto_field_ca_model = {}
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldTlsca model
        update_enrollment_crypto_field_tlsca_model = {}
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldCa model
        update_msp_crypto_field_ca_model = {}
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldComponent model
        update_msp_crypto_field_component_model = {}
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        # Construct a dict representation of a UpdateMspCryptoFieldTlsca model
        update_msp_crypto_field_tlsca_model = {}
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateEnrollmentCryptoField model
        update_enrollment_crypto_field_model = {}
        update_enrollment_crypto_field_model['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model['tlsca'] = update_enrollment_crypto_field_tlsca_model

        # Construct a dict representation of a UpdateMspCryptoField model
        update_msp_crypto_field_model = {}
        update_msp_crypto_field_model['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model['component'] = update_msp_crypto_field_component_model

        # Construct a dict representation of a UpdateOrdererBodyCrypto model
        update_orderer_body_crypto_model = {}
        update_orderer_body_crypto_model['enrollment'] = update_enrollment_crypto_field_model
        update_orderer_body_crypto_model['msp'] = update_msp_crypto_field_model

        # Construct a dict representation of a NodeOu model
        node_ou_model = {}
        node_ou_model['enabled'] = True

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a UpdateOrdererBodyResources model
        update_orderer_body_resources_model = {}
        update_orderer_body_resources_model['orderer'] = resource_object_model
        update_orderer_body_resources_model['proxy'] = resource_object_model

        # Set up parameter values
        id = 'testString'
        admin_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        config_override = config_orderer_update_model
        crypto = update_orderer_body_crypto_model
        node_ou = node_ou_model
        replicas = 1
        resources = update_orderer_body_resources_model
        version = '1.4.6-1'
        zone = '-'

        # Invoke method
        response = service.update_orderer(
            id,
            admin_certs=admin_certs,
            config_override=config_override,
            crypto=crypto,
            node_ou=node_ou,
            replicas=replicas,
            resources=resources,
            version=version,
            zone=zone,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['admin_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['config_override'] == config_orderer_update_model
        assert req_body['crypto'] == update_orderer_body_crypto_model
        assert req_body['node_ou'] == node_ou_model
        assert req_body['replicas'] == 1
        assert req_body['resources'] == update_orderer_body_resources_model
        assert req_body['version'] == '1.4.6-1'
        assert req_body['zone'] == '-'


    #--------------------------------------------------------
    # test_update_orderer_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_update_orderer_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/fabric-orderer/testString')
        mock_response = '{"id": "component-1", "dep_component_id": "admin", "api_url": "grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050", "display_name": "orderer", "grpcwp_url": "https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443", "location": "ibmcloud", "operations_url": "https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443", "orderer_type": "raft", "config_override": {"anyKey": "anyValue"}, "consenter_proposal_fin": true, "node_ou": {"enabled": true}, "msp": {"ca": {"name": "ca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "tlsca", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "resources": {"orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "storage": {"orderer": {"size": "4GiB", "class": "default"}}, "system_channel_id": "testchainid", "tags": ["fabric-ca"], "timestamp": 1537262855753, "type": "fabric-peer", "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a ConfigOrdererAuthentication model
        config_orderer_authentication_model = {}
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        # Construct a dict representation of a ConfigOrdererKeepalive model
        config_orderer_keepalive_model = {}
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        # Construct a dict representation of a ConfigOrdererMetricsStatsd model
        config_orderer_metrics_statsd_model = {}
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        # Construct a dict representation of a ConfigOrdererDebug model
        config_orderer_debug_model = {}
        config_orderer_debug_model['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model['DeliverTraceDir'] = 'testString'

        # Construct a dict representation of a ConfigOrdererGeneralUpdate model
        config_orderer_general_update_model = {}
        config_orderer_general_update_model['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_update_model['Authentication'] = config_orderer_authentication_model

        # Construct a dict representation of a ConfigOrdererMetrics model
        config_orderer_metrics_model = {}
        config_orderer_metrics_model['Provider'] = 'disabled'
        config_orderer_metrics_model['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a dict representation of a ConfigOrdererUpdate model
        config_orderer_update_model = {}
        config_orderer_update_model['General'] = config_orderer_general_update_model
        config_orderer_update_model['Debug'] = config_orderer_debug_model
        config_orderer_update_model['Metrics'] = config_orderer_metrics_model

        # Construct a dict representation of a ClientAuth model
        client_auth_model = {}
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a dict representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model = {}
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldCa model
        update_enrollment_crypto_field_ca_model = {}
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        # Construct a dict representation of a UpdateEnrollmentCryptoFieldTlsca model
        update_enrollment_crypto_field_tlsca_model = {}
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldCa model
        update_msp_crypto_field_ca_model = {}
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateMspCryptoFieldComponent model
        update_msp_crypto_field_component_model = {}
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        # Construct a dict representation of a UpdateMspCryptoFieldTlsca model
        update_msp_crypto_field_tlsca_model = {}
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        # Construct a dict representation of a UpdateEnrollmentCryptoField model
        update_enrollment_crypto_field_model = {}
        update_enrollment_crypto_field_model['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model['tlsca'] = update_enrollment_crypto_field_tlsca_model

        # Construct a dict representation of a UpdateMspCryptoField model
        update_msp_crypto_field_model = {}
        update_msp_crypto_field_model['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model['component'] = update_msp_crypto_field_component_model

        # Construct a dict representation of a UpdateOrdererBodyCrypto model
        update_orderer_body_crypto_model = {}
        update_orderer_body_crypto_model['enrollment'] = update_enrollment_crypto_field_model
        update_orderer_body_crypto_model['msp'] = update_msp_crypto_field_model

        # Construct a dict representation of a NodeOu model
        node_ou_model = {}
        node_ou_model['enabled'] = True

        # Construct a dict representation of a ResourceLimits model
        resource_limits_model = {}
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceRequests model
        resource_requests_model = {}
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a dict representation of a ResourceObject model
        resource_object_model = {}
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a dict representation of a UpdateOrdererBodyResources model
        update_orderer_body_resources_model = {}
        update_orderer_body_resources_model['orderer'] = resource_object_model
        update_orderer_body_resources_model['proxy'] = resource_object_model

        # Set up parameter values
        id = 'testString'
        admin_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        config_override = config_orderer_update_model
        crypto = update_orderer_body_crypto_model
        node_ou = node_ou_model
        replicas = 1
        resources = update_orderer_body_resources_model
        version = '1.4.6-1'
        zone = '-'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.update_orderer(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for submit_block
#-----------------------------------------------------------------------------
class TestSubmitBlock():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # submit_block()
    #--------------------------------------------------------
    @responses.activate
    def test_submit_block_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString/config')
        mock_response = '{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        b64_block = 'bWFzc2l2ZSBiaW5hcnkgb2YgYSBjb25maWcgYmxvY2sgd291bGQgYmUgaGVyZSBpZiB0aGlzIHdhcyByZWFsLCBwbGVhc2UgZG9udCBzZW5kIHRoaXM='

        # Invoke method
        response = service.submit_block(
            id,
            b64_block=b64_block,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['b64_block'] == 'bWFzc2l2ZSBiaW5hcnkgb2YgYSBjb25maWcgYmxvY2sgd291bGQgYmUgaGVyZSBpZiB0aGlzIHdhcyByZWFsLCBwbGVhc2UgZG9udCBzZW5kIHRoaXM='


    #--------------------------------------------------------
    # test_submit_block_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_submit_block_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString/config')
        mock_response = '{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        b64_block = 'bWFzc2l2ZSBiaW5hcnkgb2YgYSBjb25maWcgYmxvY2sgd291bGQgYmUgaGVyZSBpZiB0aGlzIHdhcyByZWFsLCBwbGVhc2UgZG9udCBzZW5kIHRoaXM='

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.submit_block(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for import_msp
#-----------------------------------------------------------------------------
class TestImportMsp():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # import_msp()
    #--------------------------------------------------------
    @responses.activate
    def test_import_msp_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msp')
        mock_response = '{"id": "component-1", "type": "fabric-peer", "display_name": "My Peer", "msp_id": "Org1", "timestamp": 1537262855753, "tags": ["fabric-ca"], "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "intermediate_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "scheme_version": "v1", "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        msp_id = 'Org1'
        display_name = 'My Peer'
        root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        intermediate_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        admins = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        tls_root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Invoke method
        response = service.import_msp(
            msp_id,
            display_name,
            root_certs,
            intermediate_certs=intermediate_certs,
            admins=admins,
            tls_root_certs=tls_root_certs,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['msp_id'] == 'Org1'
        assert req_body['display_name'] == 'My Peer'
        assert req_body['root_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['intermediate_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        assert req_body['admins'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['tls_root_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']


    #--------------------------------------------------------
    # test_import_msp_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_import_msp_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msp')
        mock_response = '{"id": "component-1", "type": "fabric-peer", "display_name": "My Peer", "msp_id": "Org1", "timestamp": 1537262855753, "tags": ["fabric-ca"], "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "intermediate_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "scheme_version": "v1", "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        msp_id = 'Org1'
        display_name = 'My Peer'
        root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        intermediate_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        admins = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        tls_root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "msp_id": msp_id,
            "display_name": display_name,
            "root_certs": root_certs,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.import_msp(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for edit_msp
#-----------------------------------------------------------------------------
class TestEditMsp():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # edit_msp()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_msp_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msp/testString')
        mock_response = '{"id": "component-1", "type": "fabric-peer", "display_name": "My Peer", "msp_id": "Org1", "timestamp": 1537262855753, "tags": ["fabric-ca"], "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "intermediate_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "scheme_version": "v1", "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        msp_id = 'Org1'
        display_name = 'My Peer'
        root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        intermediate_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        admins = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        tls_root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Invoke method
        response = service.edit_msp(
            id,
            msp_id=msp_id,
            display_name=display_name,
            root_certs=root_certs,
            intermediate_certs=intermediate_certs,
            admins=admins,
            tls_root_certs=tls_root_certs,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['msp_id'] == 'Org1'
        assert req_body['display_name'] == 'My Peer'
        assert req_body['root_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['intermediate_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        assert req_body['admins'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['tls_root_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']


    #--------------------------------------------------------
    # test_edit_msp_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_msp_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msp/testString')
        mock_response = '{"id": "component-1", "type": "fabric-peer", "display_name": "My Peer", "msp_id": "Org1", "timestamp": 1537262855753, "tags": ["fabric-ca"], "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "intermediate_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "scheme_version": "v1", "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        msp_id = 'Org1'
        display_name = 'My Peer'
        root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        intermediate_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        admins = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        tls_root_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.edit_msp(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for get_msp_certificate
#-----------------------------------------------------------------------------
class TestGetMspCertificate():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_msp_certificate()
    #--------------------------------------------------------
    @responses.activate
    def test_get_msp_certificate_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msps/testString')
        mock_response = '{"msps": [{"msp_id": "Org1", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        msp_id = 'testString'
        cache = 'skip'

        # Invoke method
        response = service.get_msp_certificate(
            msp_id,
            cache=cache,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'cache={}'.format(cache) in query_string


    #--------------------------------------------------------
    # test_get_msp_certificate_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_get_msp_certificate_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msps/testString')
        mock_response = '{"msps": [{"msp_id": "Org1", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        msp_id = 'testString'

        # Invoke method
        response = service.get_msp_certificate(
            msp_id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_get_msp_certificate_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_get_msp_certificate_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/msps/testString')
        mock_response = '{"msps": [{"msp_id": "Org1", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "admins": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="], "tls_root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        msp_id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "msp_id": msp_id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_msp_certificate(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for edit_admin_certs
#-----------------------------------------------------------------------------
class TestEditAdminCerts():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # edit_admin_certs()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_admin_certs_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString/certs')
        mock_response = '{"changes_made": 1, "set_admin_certs": [{"base_64_pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "issuer": "/C=US/ST=North Carolina/O=Hyperledger/OU=Fabric/CN=fabric-ca-server", "not_after_ts": 1597770420000, "not_before_ts": 1566234120000, "serial_number_hex": "649a1206fd0bc8be994886dd715cecb0a7a21276", "signature_algorithm": "SHA256withECDSA", "subject": "/OU=client/CN=admin", "X509_version": 3, "time_left": "10 hrs"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'
        append_admin_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        remove_admin_certs = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Invoke method
        response = service.edit_admin_certs(
            id,
            append_admin_certs=append_admin_certs,
            remove_admin_certs=remove_admin_certs,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['append_admin_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        assert req_body['remove_admin_certs'] == ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']


    #--------------------------------------------------------
    # test_edit_admin_certs_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_admin_certs_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString/certs')
        mock_response = '{"changes_made": 1, "set_admin_certs": [{"base_64_pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "issuer": "/C=US/ST=North Carolina/O=Hyperledger/OU=Fabric/CN=fabric-ca-server", "not_after_ts": 1597770420000, "not_before_ts": 1566234120000, "serial_number_hex": "649a1206fd0bc8be994886dd715cecb0a7a21276", "signature_algorithm": "SHA256withECDSA", "subject": "/OU=client/CN=admin", "X509_version": 3, "time_left": "10 hrs"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.edit_admin_certs(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_edit_admin_certs_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_admin_certs_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/testString/certs')
        mock_response = '{"changes_made": 1, "set_admin_certs": [{"base_64_pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "issuer": "/C=US/ST=North Carolina/O=Hyperledger/OU=Fabric/CN=fabric-ca-server", "not_after_ts": 1597770420000, "not_before_ts": 1566234120000, "serial_number_hex": "649a1206fd0bc8be994886dd715cecb0a7a21276", "signature_algorithm": "SHA256withECDSA", "subject": "/OU=client/CN=admin", "X509_version": 3, "time_left": "10 hrs"}]}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.edit_admin_certs(**req_copy)



# endregion
##############################################################################
# End of Service: ManageComponent
##############################################################################

##############################################################################
# Start of Service: ManageMultipleComponents
##############################################################################
# region

#-----------------------------------------------------------------------------
# Test Class for list_components
#-----------------------------------------------------------------------------
class TestListComponents():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # list_components()
    #--------------------------------------------------------
    @responses.activate
    def test_list_components_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        deployment_attrs = 'included'
        parsed_certs = 'included'
        cache = 'skip'
        ca_attrs = 'included'

        # Invoke method
        response = service.list_components(
            deployment_attrs=deployment_attrs,
            parsed_certs=parsed_certs,
            cache=cache,
            ca_attrs=ca_attrs,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'deployment_attrs={}'.format(deployment_attrs) in query_string
        assert 'parsed_certs={}'.format(parsed_certs) in query_string
        assert 'cache={}'.format(cache) in query_string
        assert 'ca_attrs={}'.format(ca_attrs) in query_string


    #--------------------------------------------------------
    # test_list_components_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_list_components_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.list_components()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for get_components_by_type
#-----------------------------------------------------------------------------
class TestGetComponentsByType():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_components_by_type()
    #--------------------------------------------------------
    @responses.activate
    def test_get_components_by_type_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/types/fabric-peer')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        component_type = 'fabric-peer'
        deployment_attrs = 'included'
        parsed_certs = 'included'
        cache = 'skip'

        # Invoke method
        response = service.get_components_by_type(
            component_type,
            deployment_attrs=deployment_attrs,
            parsed_certs=parsed_certs,
            cache=cache,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'deployment_attrs={}'.format(deployment_attrs) in query_string
        assert 'parsed_certs={}'.format(parsed_certs) in query_string
        assert 'cache={}'.format(cache) in query_string


    #--------------------------------------------------------
    # test_get_components_by_type_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_get_components_by_type_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/types/fabric-peer')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        component_type = 'fabric-peer'

        # Invoke method
        response = service.get_components_by_type(
            component_type,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_get_components_by_type_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_get_components_by_type_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/types/fabric-peer')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        component_type = 'fabric-peer'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "component_type": component_type,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_components_by_type(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for get_components_by_tag
#-----------------------------------------------------------------------------
class TestGetComponentsByTag():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_components_by_tag()
    #--------------------------------------------------------
    @responses.activate
    def test_get_components_by_tag_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/tags/testString')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'
        deployment_attrs = 'included'
        parsed_certs = 'included'
        cache = 'skip'

        # Invoke method
        response = service.get_components_by_tag(
            tag,
            deployment_attrs=deployment_attrs,
            parsed_certs=parsed_certs,
            cache=cache,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'deployment_attrs={}'.format(deployment_attrs) in query_string
        assert 'parsed_certs={}'.format(parsed_certs) in query_string
        assert 'cache={}'.format(cache) in query_string


    #--------------------------------------------------------
    # test_get_components_by_tag_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_get_components_by_tag_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/tags/testString')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'

        # Invoke method
        response = service.get_components_by_tag(
            tag,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_get_components_by_tag_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_get_components_by_tag_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/tags/testString')
        mock_response = '{"components": [{"id": "myca-2", "type": "fabric-ca", "display_name": "Example CA", "grpcwp_url": "https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084", "api_url": "grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051", "operations_url": "https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443", "msp": {"ca": {"name": "org1CA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "tlsca": {"name": "org1tlsCA", "root_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}, "component": {"tls_cert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "ecert": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=", "admin_certs": ["LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="]}}, "msp_id": "Org1", "location": "ibmcloud", "node_ou": {"enabled": true}, "resources": {"ca": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "peer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "orderer": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "proxy": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}, "statedb": {"requests": {"cpu": "100m", "memory": "256M"}, "limits": {"cpu": "8000m", "memory": "16384M"}}}, "scheme_version": "v1", "state_db": "couchdb", "storage": {"ca": {"size": "4GiB", "class": "default"}, "peer": {"size": "4GiB", "class": "default"}, "orderer": {"size": "4GiB", "class": "default"}, "statedb": {"size": "4GiB", "class": "default"}}, "timestamp": 1537262855753, "tags": ["fabric-ca"], "version": "1.4.6-1", "zone": "-"}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "tag": tag,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_components_by_tag(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for remove_components_by_tag
#-----------------------------------------------------------------------------
class TestRemoveComponentsByTag():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # remove_components_by_tag()
    #--------------------------------------------------------
    @responses.activate
    def test_remove_components_by_tag_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/tags/testString')
        mock_response = '{"removed": [{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}]}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'

        # Invoke method
        response = service.remove_components_by_tag(
            tag,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_remove_components_by_tag_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_remove_components_by_tag_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/components/tags/testString')
        mock_response = '{"removed": [{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}]}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "tag": tag,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.remove_components_by_tag(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for delete_components_by_tag
#-----------------------------------------------------------------------------
class TestDeleteComponentsByTag():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # delete_components_by_tag()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_components_by_tag_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/tags/testString')
        mock_response = '{"deleted": [{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}]}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'

        # Invoke method
        response = service.delete_components_by_tag(
            tag,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_delete_components_by_tag_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_components_by_tag_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/tags/testString')
        mock_response = '{"deleted": [{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}]}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        tag = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "tag": tag,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.delete_components_by_tag(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for delete_all_components
#-----------------------------------------------------------------------------
class TestDeleteAllComponents():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # delete_all_components()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_all_components_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/components/purge')
        mock_response = '{"deleted": [{"message": "deleted", "type": "fabric-peer", "id": "component-1", "display_name": "My Peer"}]}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.delete_all_components()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


# endregion
##############################################################################
# End of Service: ManageMultipleComponents
##############################################################################

##############################################################################
# Start of Service: AdministerTheIBPConsole
##############################################################################
# region

#-----------------------------------------------------------------------------
# Test Class for get_settings
#-----------------------------------------------------------------------------
class TestGetSettings():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_settings()
    #--------------------------------------------------------
    @responses.activate
    def test_get_settings_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/settings')
        mock_response = '{"ACTIVITY_TRACKER_PATH": "/logs", "ATHENA_ID": "17v7e", "AUTH_SCHEME": "iam", "CALLBACK_URI": "/auth/cb", "CLUSTER_DATA": {"type": "paid"}, "CONFIGTXLATOR_URL": "https://n3a3ec3-configtxlator.ibp.us-south.containers.appdomain.cloud", "CRN": {"account_id": "a/abcd", "c_name": "staging", "c_type": "public", "instance_id": "abc123", "location": "us-south", "resource_id": "-", "resource_type": "-", "service_name": "blockchain", "version": "v1"}, "CRN_STRING": "crn:v1:staging:public:blockchain:us-south:a/abcd:abc123::", "CSP_HEADER_VALUES": ["-"], "DB_SYSTEM": "system", "DEPLOYER_URL": "https://api.dev.blockchain.cloud.ibm.com", "DOMAIN": "localhost", "ENVIRONMENT": "prod", "FABRIC_CAPABILITIES": {"application": ["V1_1"], "channel": ["V1_1"], "orderer": ["V1_1"]}, "FEATURE_FLAGS": {"anyKey": "anyValue"}, "FILE_LOGGING": {"server": {"client": {"enabled": true, "level": "silly", "unique_name": false}, "server": {"enabled": true, "level": "silly", "unique_name": false}}, "client": {"client": {"enabled": true, "level": "silly", "unique_name": false}, "server": {"enabled": true, "level": "silly", "unique_name": false}}}, "HOST_URL": "http://localhost:3000", "IAM_CACHE_ENABLED": true, "IAM_URL": "-", "IBM_ID_CALLBACK_URL": "http://localhost:3000/auth/login", "IGNORE_CONFIG_FILE": true, "INACTIVITY_TIMEOUTS": {"enabled": true, "max_idle_time": 60000}, "INFRASTRUCTURE": "ibmcloud", "LANDING_URL": "http://localhost:3000", "LOGIN_URI": "/auth/login", "LOGOUT_URI": "/auth/logout", "MAX_REQ_PER_MIN": 25, "MAX_REQ_PER_MIN_AK": 25, "MEMORY_CACHE_ENABLED": true, "PORT": "3000", "PROXY_CACHE_ENABLED": true, "PROXY_TLS_FABRIC_REQS": "always", "PROXY_TLS_HTTP_URL": "http://localhost:3000", "PROXY_TLS_WS_URL": {"anyKey": "anyValue"}, "REGION": "us_south", "SESSION_CACHE_ENABLED": true, "TIMEOUTS": {"anyKey": "anyValue"}, "TIMESTAMPS": {"now": 1542746836056, "born": 1542746836056, "next_settings_update": "1.2 mins", "up_time": "30 days"}, "TRANSACTION_VISIBILITY": {"anyKey": "anyValue"}, "TRUST_PROXY": "loopback", "TRUST_UNKNOWN_CERTS": true, "VERSIONS": {"apollo": "65f3cbfd", "athena": "1198f94", "stitch": "0f1a0c6", "tag": "v0.4.31"}}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.get_settings()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for edit_settings
#-----------------------------------------------------------------------------
class TestEditSettings():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # edit_settings()
    #--------------------------------------------------------
    @responses.activate
    def test_edit_settings_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/settings')
        mock_response = '{"ACTIVITY_TRACKER_PATH": "/logs", "ATHENA_ID": "17v7e", "AUTH_SCHEME": "iam", "CALLBACK_URI": "/auth/cb", "CLUSTER_DATA": {"type": "paid"}, "CONFIGTXLATOR_URL": "https://n3a3ec3-configtxlator.ibp.us-south.containers.appdomain.cloud", "CRN": {"account_id": "a/abcd", "c_name": "staging", "c_type": "public", "instance_id": "abc123", "location": "us-south", "resource_id": "-", "resource_type": "-", "service_name": "blockchain", "version": "v1"}, "CRN_STRING": "crn:v1:staging:public:blockchain:us-south:a/abcd:abc123::", "CSP_HEADER_VALUES": ["-"], "DB_SYSTEM": "system", "DEPLOYER_URL": "https://api.dev.blockchain.cloud.ibm.com", "DOMAIN": "localhost", "ENVIRONMENT": "prod", "FABRIC_CAPABILITIES": {"application": ["V1_1"], "channel": ["V1_1"], "orderer": ["V1_1"]}, "FEATURE_FLAGS": {"anyKey": "anyValue"}, "FILE_LOGGING": {"server": {"client": {"enabled": true, "level": "silly", "unique_name": false}, "server": {"enabled": true, "level": "silly", "unique_name": false}}, "client": {"client": {"enabled": true, "level": "silly", "unique_name": false}, "server": {"enabled": true, "level": "silly", "unique_name": false}}}, "HOST_URL": "http://localhost:3000", "IAM_CACHE_ENABLED": true, "IAM_URL": "-", "IBM_ID_CALLBACK_URL": "http://localhost:3000/auth/login", "IGNORE_CONFIG_FILE": true, "INACTIVITY_TIMEOUTS": {"enabled": true, "max_idle_time": 60000}, "INFRASTRUCTURE": "ibmcloud", "LANDING_URL": "http://localhost:3000", "LOGIN_URI": "/auth/login", "LOGOUT_URI": "/auth/logout", "MAX_REQ_PER_MIN": 25, "MAX_REQ_PER_MIN_AK": 25, "MEMORY_CACHE_ENABLED": true, "PORT": "3000", "PROXY_CACHE_ENABLED": true, "PROXY_TLS_FABRIC_REQS": "always", "PROXY_TLS_HTTP_URL": "http://localhost:3000", "PROXY_TLS_WS_URL": {"anyKey": "anyValue"}, "REGION": "us_south", "SESSION_CACHE_ENABLED": true, "TIMEOUTS": {"anyKey": "anyValue"}, "TIMESTAMPS": {"now": 1542746836056, "born": 1542746836056, "next_settings_update": "1.2 mins", "up_time": "30 days"}, "TRANSACTION_VISIBILITY": {"anyKey": "anyValue"}, "TRUST_PROXY": "loopback", "TRUST_UNKNOWN_CERTS": true, "VERSIONS": {"apollo": "65f3cbfd", "athena": "1198f94", "stitch": "0f1a0c6", "tag": "v0.4.31"}}'
        responses.add(responses.PUT,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Construct a dict representation of a EditSettingsBodyInactivityTimeouts model
        edit_settings_body_inactivity_timeouts_model = {}
        edit_settings_body_inactivity_timeouts_model['enabled'] = False
        edit_settings_body_inactivity_timeouts_model['max_idle_time'] = 90000

        # Construct a dict representation of a LoggingSettingsClient model
        logging_settings_client_model = {}
        logging_settings_client_model['enabled'] = True
        logging_settings_client_model['level'] = 'silly'
        logging_settings_client_model['unique_name'] = False

        # Construct a dict representation of a LoggingSettingsServer model
        logging_settings_server_model = {}
        logging_settings_server_model['enabled'] = True
        logging_settings_server_model['level'] = 'silly'
        logging_settings_server_model['unique_name'] = False

        # Construct a dict representation of a EditLogSettingsBody model
        edit_log_settings_body_model = {}
        edit_log_settings_body_model['client'] = logging_settings_client_model
        edit_log_settings_body_model['server'] = logging_settings_server_model

        # Set up parameter values
        inactivity_timeouts = edit_settings_body_inactivity_timeouts_model
        file_logging = edit_log_settings_body_model
        max_req_per_min = 25
        max_req_per_min_ak = 25
        fabric_get_block_timeout_ms = 10000
        fabric_instantiate_timeout_ms = 300000
        fabric_join_channel_timeout_ms = 25000
        fabric_install_cc_timeout_ms = 300000
        fabric_lc_install_cc_timeout_ms = 300000
        fabric_lc_get_cc_timeout_ms = 180000
        fabric_general_timeout_ms = 10000

        # Invoke method
        response = service.edit_settings(
            inactivity_timeouts=inactivity_timeouts,
            file_logging=file_logging,
            max_req_per_min=max_req_per_min,
            max_req_per_min_ak=max_req_per_min_ak,
            fabric_get_block_timeout_ms=fabric_get_block_timeout_ms,
            fabric_instantiate_timeout_ms=fabric_instantiate_timeout_ms,
            fabric_join_channel_timeout_ms=fabric_join_channel_timeout_ms,
            fabric_install_cc_timeout_ms=fabric_install_cc_timeout_ms,
            fabric_lc_install_cc_timeout_ms=fabric_lc_install_cc_timeout_ms,
            fabric_lc_get_cc_timeout_ms=fabric_lc_get_cc_timeout_ms,
            fabric_general_timeout_ms=fabric_general_timeout_ms,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['inactivity_timeouts'] == edit_settings_body_inactivity_timeouts_model
        assert req_body['file_logging'] == edit_log_settings_body_model
        assert req_body['max_req_per_min'] == 25
        assert req_body['max_req_per_min_ak'] == 25
        assert req_body['fabric_get_block_timeout_ms'] == 10000
        assert req_body['fabric_instantiate_timeout_ms'] == 300000
        assert req_body['fabric_join_channel_timeout_ms'] == 25000
        assert req_body['fabric_install_cc_timeout_ms'] == 300000
        assert req_body['fabric_lc_install_cc_timeout_ms'] == 300000
        assert req_body['fabric_lc_get_cc_timeout_ms'] == 180000
        assert req_body['fabric_general_timeout_ms'] == 10000


#-----------------------------------------------------------------------------
# Test Class for get_fab_versions
#-----------------------------------------------------------------------------
class TestGetFabVersions():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_fab_versions()
    #--------------------------------------------------------
    @responses.activate
    def test_get_fab_versions_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/fabric/versions')
        mock_response = '{"versions": {"ca": {"1.4.6-2": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}, "2.1.0-0": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}}, "peer": {"1.4.6-2": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}, "2.1.0-0": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}}, "orderer": {"1.4.6-2": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}, "2.1.0-0": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}}}}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        cache = 'skip'

        # Invoke method
        response = service.get_fab_versions(
            cache=cache,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'cache={}'.format(cache) in query_string


    #--------------------------------------------------------
    # test_get_fab_versions_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_get_fab_versions_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/kubernetes/fabric/versions')
        mock_response = '{"versions": {"ca": {"1.4.6-2": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}, "2.1.0-0": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}}, "peer": {"1.4.6-2": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}, "2.1.0-0": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}}, "orderer": {"1.4.6-2": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}, "2.1.0-0": {"default": true, "version": "1.4.6-2", "image": {"anyKey": "anyValue"}}}}}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.get_fab_versions()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for get_health
#-----------------------------------------------------------------------------
class TestGetHealth():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_health()
    #--------------------------------------------------------
    @responses.activate
    def test_get_health_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/health')
        mock_response = '{"OPTOOLS": {"instance_id": "p59ta", "now": 1542746836056, "born": 1542746836056, "up_time": "30 days", "memory_usage": {"rss": "56.1 MB", "heapTotal": "34.4 MB", "heapUsed": "28.4 MB", "external": "369.3 KB"}, "session_cache_stats": {"hits": 42, "misses": 11, "keys": 100, "cache_size": "4.19 KiB"}, "couch_cache_stats": {"hits": 42, "misses": 11, "keys": 100, "cache_size": "4.19 KiB"}, "iam_cache_stats": {"hits": 42, "misses": 11, "keys": 100, "cache_size": "4.19 KiB"}, "proxy_cache": {"hits": 42, "misses": 11, "keys": 100, "cache_size": "4.19 KiB"}}, "OS": {"arch": "x64", "type": "Windows_NT", "endian": "LE", "loadavg": [0], "cpus": [{"model": "Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz", "speed": 2592, "times": {"idle": 131397203, "irq": 6068640, "nice": 0, "sys": 9652328, "user": 4152187}}], "total_memory": "31.7 GB", "free_memory": "21.9 GB", "up_time": "4.9 days"}}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.get_health()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for list_notifications
#-----------------------------------------------------------------------------
class TestListNotifications():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # list_notifications()
    #--------------------------------------------------------
    @responses.activate
    def test_list_notifications_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/notifications')
        mock_response = '{"total": 10, "returning": 3, "notifications": [{"id": "60d84819bfa17adb4174ff3a1c52b5d6", "type": "notification", "status": "pending", "by": "d******a@us.ibm.com", "message": "Restarting application", "ts_display": 1537262855753}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        limit = 1
        skip = 1
        component_id = 'MyPeer'

        # Invoke method
        response = service.list_notifications(
            limit=limit,
            skip=skip,
            component_id=component_id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'limit={}'.format(limit) in query_string
        assert 'skip={}'.format(skip) in query_string
        assert 'component_id={}'.format(component_id) in query_string


    #--------------------------------------------------------
    # test_list_notifications_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_list_notifications_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/notifications')
        mock_response = '{"total": 10, "returning": 3, "notifications": [{"id": "60d84819bfa17adb4174ff3a1c52b5d6", "type": "notification", "status": "pending", "by": "d******a@us.ibm.com", "message": "Restarting application", "ts_display": 1537262855753}]}'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.list_notifications()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for delete_sig_tx
#-----------------------------------------------------------------------------
class TestDeleteSigTx():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # delete_sig_tx()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_sig_tx_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/signature_collections/testString')
        mock_response = '{"message": "ok", "tx_id": "abcde"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Invoke method
        response = service.delete_sig_tx(
            id,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


    #--------------------------------------------------------
    # test_delete_sig_tx_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_sig_tx_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/signature_collections/testString')
        mock_response = '{"message": "ok", "tx_id": "abcde"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        id = 'testString'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "id": id,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.delete_sig_tx(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for archive_notifications
#-----------------------------------------------------------------------------
class TestArchiveNotifications():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # archive_notifications()
    #--------------------------------------------------------
    @responses.activate
    def test_archive_notifications_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/notifications/bulk')
        mock_response = '{"message": "ok", "details": "archived 3 notification(s)"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        notification_ids = ['c9d00ebf849051e4f102008dc0be2488']

        # Invoke method
        response = service.archive_notifications(
            notification_ids,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate body params
        req_body = json.loads(str(responses.calls[0].request.body, 'utf-8'))
        assert req_body['notification_ids'] == ['c9d00ebf849051e4f102008dc0be2488']


    #--------------------------------------------------------
    # test_archive_notifications_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_archive_notifications_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/notifications/bulk')
        mock_response = '{"message": "ok", "details": "archived 3 notification(s)"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Set up parameter values
        notification_ids = ['c9d00ebf849051e4f102008dc0be2488']

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "notification_ids": notification_ids,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.archive_notifications(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for restart
#-----------------------------------------------------------------------------
class TestRestart():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # restart()
    #--------------------------------------------------------
    @responses.activate
    def test_restart_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/restart')
        mock_response = '{"message": "restarting - give me 5-30 seconds"}'
        responses.add(responses.POST,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.restart()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for delete_all_sessions
#-----------------------------------------------------------------------------
class TestDeleteAllSessions():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # delete_all_sessions()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_all_sessions_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/sessions')
        mock_response = '{"message": "delete submitted"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.delete_all_sessions()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for delete_all_notifications
#-----------------------------------------------------------------------------
class TestDeleteAllNotifications():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # delete_all_notifications()
    #--------------------------------------------------------
    @responses.activate
    def test_delete_all_notifications_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/notifications/purge')
        mock_response = '{"message": "ok", "details": "deleted 101 notification(s)"}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.delete_all_notifications()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


#-----------------------------------------------------------------------------
# Test Class for clear_caches
#-----------------------------------------------------------------------------
class TestClearCaches():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # clear_caches()
    #--------------------------------------------------------
    @responses.activate
    def test_clear_caches_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/cache')
        mock_response = '{"message": "ok", "flushed": ["iam_cache"]}'
        responses.add(responses.DELETE,
                      url,
                      body=mock_response,
                      content_type='application/json',
                      status=200)

        # Invoke method
        response = service.clear_caches()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


# endregion
##############################################################################
# End of Service: AdministerTheIBPConsole
##############################################################################

##############################################################################
# Start of Service: DownloadExamples
##############################################################################
# region

#-----------------------------------------------------------------------------
# Test Class for get_postman
#-----------------------------------------------------------------------------
class TestGetPostman():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_postman()
    #--------------------------------------------------------
    @responses.activate
    def test_get_postman_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/postman')
        responses.add(responses.GET,
                      url,
                      status=200)

        # Set up parameter values
        auth_type = 'bearer'
        token = 'testString'
        api_key = 'testString'
        username = 'admin'
        password = 'password'

        # Invoke method
        response = service.get_postman(
            auth_type,
            token=token,
            api_key=api_key,
            username=username,
            password=password,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'auth_type={}'.format(auth_type) in query_string
        assert 'token={}'.format(token) in query_string
        assert 'api_key={}'.format(api_key) in query_string
        assert 'username={}'.format(username) in query_string
        assert 'password={}'.format(password) in query_string


    #--------------------------------------------------------
    # test_get_postman_required_params()
    #--------------------------------------------------------
    @responses.activate
    def test_get_postman_required_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/postman')
        responses.add(responses.GET,
                      url,
                      status=200)

        # Set up parameter values
        auth_type = 'bearer'

        # Invoke method
        response = service.get_postman(
            auth_type,
            headers={}
        )

        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200
        # Validate query params
        query_string = responses.calls[0].request.url.split('?',1)[1]
        query_string = requests.utils.unquote(query_string)
        assert 'auth_type={}'.format(auth_type) in query_string


    #--------------------------------------------------------
    # test_get_postman_value_error()
    #--------------------------------------------------------
    @responses.activate
    def test_get_postman_value_error(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/postman')
        responses.add(responses.GET,
                      url,
                      status=200)

        # Set up parameter values
        auth_type = 'bearer'

        # Pass in all but one required param and check for a ValueError
        req_param_dict = {
            "auth_type": auth_type,
        }
        for param in req_param_dict.keys():
            req_copy = {key:val if key is not param else None for (key,val) in req_param_dict.items()}
            with pytest.raises(ValueError):
                service.get_postman(**req_copy)



#-----------------------------------------------------------------------------
# Test Class for get_swagger
#-----------------------------------------------------------------------------
class TestGetSwagger():

    # Preprocess the request URL to ensure the mock response will be found.
    def preprocess_url(self, request_url: str):
        if re.fullmatch('.*/+', request_url) is None:
            return request_url
        else:
            return re.compile(request_url.rstrip('/') + '/+')

    #--------------------------------------------------------
    # get_swagger()
    #--------------------------------------------------------
    @responses.activate
    def test_get_swagger_all_params(self):
        # Set up mock
        url = self.preprocess_url(base_url + '/ak/api/v3/openapi')
        mock_response = '"operation_response"'
        responses.add(responses.GET,
                      url,
                      body=mock_response,
                      content_type='text/plain',
                      status=200)

        # Invoke method
        response = service.get_swagger()


        # Check for correct operation
        assert len(responses.calls) == 1
        assert response.status_code == 200


# endregion
##############################################################################
# End of Service: DownloadExamples
##############################################################################


##############################################################################
# Start of Model Tests
##############################################################################
# region
#-----------------------------------------------------------------------------
# Test Class for ActionsResponse
#-----------------------------------------------------------------------------
class TestActionsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for ActionsResponse
    #--------------------------------------------------------
    def test_actions_response_serialization(self):

        # Construct a json representation of a ActionsResponse model
        actions_response_model_json = {}
        actions_response_model_json['message'] = 'accepted'
        actions_response_model_json['id'] = 'myca'
        actions_response_model_json['actions'] = ['restart']

        # Construct a model instance of ActionsResponse by calling from_dict on the json representation
        actions_response_model = ActionsResponse.from_dict(actions_response_model_json)
        assert actions_response_model != False

        # Construct a model instance of ActionsResponse by calling from_dict on the json representation
        actions_response_model_dict = ActionsResponse.from_dict(actions_response_model_json).__dict__
        actions_response_model2 = ActionsResponse(**actions_response_model_dict)

        # Verify the model instances are equivalent
        assert actions_response_model == actions_response_model2

        # Convert model instance back to dict and verify no loss of data
        actions_response_model_json2 = actions_response_model.to_dict()
        assert actions_response_model_json2 == actions_response_model_json

#-----------------------------------------------------------------------------
# Test Class for ArchiveResponse
#-----------------------------------------------------------------------------
class TestArchiveResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for ArchiveResponse
    #--------------------------------------------------------
    def test_archive_response_serialization(self):

        # Construct a json representation of a ArchiveResponse model
        archive_response_model_json = {}
        archive_response_model_json['message'] = 'ok'
        archive_response_model_json['details'] = 'archived 3 notification(s)'

        # Construct a model instance of ArchiveResponse by calling from_dict on the json representation
        archive_response_model = ArchiveResponse.from_dict(archive_response_model_json)
        assert archive_response_model != False

        # Construct a model instance of ArchiveResponse by calling from_dict on the json representation
        archive_response_model_dict = ArchiveResponse.from_dict(archive_response_model_json).__dict__
        archive_response_model2 = ArchiveResponse(**archive_response_model_dict)

        # Verify the model instances are equivalent
        assert archive_response_model == archive_response_model2

        # Convert model instance back to dict and verify no loss of data
        archive_response_model_json2 = archive_response_model.to_dict()
        assert archive_response_model_json2 == archive_response_model_json

#-----------------------------------------------------------------------------
# Test Class for Bccsp
#-----------------------------------------------------------------------------
class TestBccsp():

    #--------------------------------------------------------
    # Test serialization/deserialization for Bccsp
    #--------------------------------------------------------
    def test_bccsp_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        # Construct a json representation of a Bccsp model
        bccsp_model_json = {}
        bccsp_model_json['Default'] = 'SW'
        bccsp_model_json['SW'] = bccsp_sw_model
        bccsp_model_json['PKCS11'] = bccsp_pkc_s11_model

        # Construct a model instance of Bccsp by calling from_dict on the json representation
        bccsp_model = Bccsp.from_dict(bccsp_model_json)
        assert bccsp_model != False

        # Construct a model instance of Bccsp by calling from_dict on the json representation
        bccsp_model_dict = Bccsp.from_dict(bccsp_model_json).__dict__
        bccsp_model2 = Bccsp(**bccsp_model_dict)

        # Verify the model instances are equivalent
        assert bccsp_model == bccsp_model2

        # Convert model instance back to dict and verify no loss of data
        bccsp_model_json2 = bccsp_model.to_dict()
        assert bccsp_model_json2 == bccsp_model_json

#-----------------------------------------------------------------------------
# Test Class for BccspPKCS11
#-----------------------------------------------------------------------------
class TestBccspPKCS11():

    #--------------------------------------------------------
    # Test serialization/deserialization for BccspPKCS11
    #--------------------------------------------------------
    def test_bccsp_pkc_s11_serialization(self):

        # Construct a json representation of a BccspPKCS11 model
        bccsp_pkc_s11_model_json = {}
        bccsp_pkc_s11_model_json['Label'] = 'testString'
        bccsp_pkc_s11_model_json['Pin'] = 'testString'
        bccsp_pkc_s11_model_json['Hash'] = 'SHA2'
        bccsp_pkc_s11_model_json['Security'] = 256

        # Construct a model instance of BccspPKCS11 by calling from_dict on the json representation
        bccsp_pkc_s11_model = BccspPKCS11.from_dict(bccsp_pkc_s11_model_json)
        assert bccsp_pkc_s11_model != False

        # Construct a model instance of BccspPKCS11 by calling from_dict on the json representation
        bccsp_pkc_s11_model_dict = BccspPKCS11.from_dict(bccsp_pkc_s11_model_json).__dict__
        bccsp_pkc_s11_model2 = BccspPKCS11(**bccsp_pkc_s11_model_dict)

        # Verify the model instances are equivalent
        assert bccsp_pkc_s11_model == bccsp_pkc_s11_model2

        # Convert model instance back to dict and verify no loss of data
        bccsp_pkc_s11_model_json2 = bccsp_pkc_s11_model.to_dict()
        assert bccsp_pkc_s11_model_json2 == bccsp_pkc_s11_model_json

#-----------------------------------------------------------------------------
# Test Class for BccspSW
#-----------------------------------------------------------------------------
class TestBccspSW():

    #--------------------------------------------------------
    # Test serialization/deserialization for BccspSW
    #--------------------------------------------------------
    def test_bccsp_sw_serialization(self):

        # Construct a json representation of a BccspSW model
        bccsp_sw_model_json = {}
        bccsp_sw_model_json['Hash'] = 'SHA2'
        bccsp_sw_model_json['Security'] = 256

        # Construct a model instance of BccspSW by calling from_dict on the json representation
        bccsp_sw_model = BccspSW.from_dict(bccsp_sw_model_json)
        assert bccsp_sw_model != False

        # Construct a model instance of BccspSW by calling from_dict on the json representation
        bccsp_sw_model_dict = BccspSW.from_dict(bccsp_sw_model_json).__dict__
        bccsp_sw_model2 = BccspSW(**bccsp_sw_model_dict)

        # Verify the model instances are equivalent
        assert bccsp_sw_model == bccsp_sw_model2

        # Convert model instance back to dict and verify no loss of data
        bccsp_sw_model_json2 = bccsp_sw_model.to_dict()
        assert bccsp_sw_model_json2 == bccsp_sw_model_json

#-----------------------------------------------------------------------------
# Test Class for CaResponse
#-----------------------------------------------------------------------------
class TestCaResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for CaResponse
    #--------------------------------------------------------
    def test_ca_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        msp_crypto_field_ca_model = {} # MspCryptoFieldCa
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_component_model = {} # MspCryptoFieldComponent
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_tlsca_model = {} # MspCryptoFieldTlsca
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        ca_response_resources_model = {} # CaResponseResources
        ca_response_resources_model['ca'] = generic_resources_model

        ca_response_storage_model = {} # CaResponseStorage
        ca_response_storage_model['ca'] = storage_object_model

        msp_crypto_field_model = {} # MspCryptoField
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        # Construct a json representation of a CaResponse model
        ca_response_model_json = {}
        ca_response_model_json['id'] = 'component-1'
        ca_response_model_json['dep_component_id'] = 'admin'
        ca_response_model_json['display_name'] = 'My CA'
        ca_response_model_json['api_url'] = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        ca_response_model_json['operations_url'] = 'https://n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud:9443'
        ca_response_model_json['config_override'] = { 'foo': 'bar' }
        ca_response_model_json['location'] = 'ibmcloud'
        ca_response_model_json['msp'] = msp_crypto_field_model
        ca_response_model_json['resources'] = ca_response_resources_model
        ca_response_model_json['scheme_version'] = 'v1'
        ca_response_model_json['storage'] = ca_response_storage_model
        ca_response_model_json['tags'] = ['fabric-ca']
        ca_response_model_json['timestamp'] = 1537262855753
        ca_response_model_json['version'] = '1.4.6-1'
        ca_response_model_json['zone'] = '-'

        # Construct a model instance of CaResponse by calling from_dict on the json representation
        ca_response_model = CaResponse.from_dict(ca_response_model_json)
        assert ca_response_model != False

        # Construct a model instance of CaResponse by calling from_dict on the json representation
        ca_response_model_dict = CaResponse.from_dict(ca_response_model_json).__dict__
        ca_response_model2 = CaResponse(**ca_response_model_dict)

        # Verify the model instances are equivalent
        assert ca_response_model == ca_response_model2

        # Convert model instance back to dict and verify no loss of data
        ca_response_model_json2 = ca_response_model.to_dict()
        assert ca_response_model_json2 == ca_response_model_json

#-----------------------------------------------------------------------------
# Test Class for CaResponseResources
#-----------------------------------------------------------------------------
class TestCaResponseResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for CaResponseResources
    #--------------------------------------------------------
    def test_ca_response_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        # Construct a json representation of a CaResponseResources model
        ca_response_resources_model_json = {}
        ca_response_resources_model_json['ca'] = generic_resources_model

        # Construct a model instance of CaResponseResources by calling from_dict on the json representation
        ca_response_resources_model = CaResponseResources.from_dict(ca_response_resources_model_json)
        assert ca_response_resources_model != False

        # Construct a model instance of CaResponseResources by calling from_dict on the json representation
        ca_response_resources_model_dict = CaResponseResources.from_dict(ca_response_resources_model_json).__dict__
        ca_response_resources_model2 = CaResponseResources(**ca_response_resources_model_dict)

        # Verify the model instances are equivalent
        assert ca_response_resources_model == ca_response_resources_model2

        # Convert model instance back to dict and verify no loss of data
        ca_response_resources_model_json2 = ca_response_resources_model.to_dict()
        assert ca_response_resources_model_json2 == ca_response_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for CaResponseStorage
#-----------------------------------------------------------------------------
class TestCaResponseStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for CaResponseStorage
    #--------------------------------------------------------
    def test_ca_response_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a CaResponseStorage model
        ca_response_storage_model_json = {}
        ca_response_storage_model_json['ca'] = storage_object_model

        # Construct a model instance of CaResponseStorage by calling from_dict on the json representation
        ca_response_storage_model = CaResponseStorage.from_dict(ca_response_storage_model_json)
        assert ca_response_storage_model != False

        # Construct a model instance of CaResponseStorage by calling from_dict on the json representation
        ca_response_storage_model_dict = CaResponseStorage.from_dict(ca_response_storage_model_json).__dict__
        ca_response_storage_model2 = CaResponseStorage(**ca_response_storage_model_dict)

        # Verify the model instances are equivalent
        assert ca_response_storage_model == ca_response_storage_model2

        # Convert model instance back to dict and verify no loss of data
        ca_response_storage_model_json2 = ca_response_storage_model.to_dict()
        assert ca_response_storage_model_json2 == ca_response_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for CacheData
#-----------------------------------------------------------------------------
class TestCacheData():

    #--------------------------------------------------------
    # Test serialization/deserialization for CacheData
    #--------------------------------------------------------
    def test_cache_data_serialization(self):

        # Construct a json representation of a CacheData model
        cache_data_model_json = {}
        cache_data_model_json['hits'] = 42
        cache_data_model_json['misses'] = 11
        cache_data_model_json['keys'] = 100
        cache_data_model_json['cache_size'] = '4.19 KiB'

        # Construct a model instance of CacheData by calling from_dict on the json representation
        cache_data_model = CacheData.from_dict(cache_data_model_json)
        assert cache_data_model != False

        # Construct a model instance of CacheData by calling from_dict on the json representation
        cache_data_model_dict = CacheData.from_dict(cache_data_model_json).__dict__
        cache_data_model2 = CacheData(**cache_data_model_dict)

        # Verify the model instances are equivalent
        assert cache_data_model == cache_data_model2

        # Convert model instance back to dict and verify no loss of data
        cache_data_model_json2 = cache_data_model.to_dict()
        assert cache_data_model_json2 == cache_data_model_json

#-----------------------------------------------------------------------------
# Test Class for CacheFlushResponse
#-----------------------------------------------------------------------------
class TestCacheFlushResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for CacheFlushResponse
    #--------------------------------------------------------
    def test_cache_flush_response_serialization(self):

        # Construct a json representation of a CacheFlushResponse model
        cache_flush_response_model_json = {}
        cache_flush_response_model_json['message'] = 'ok'
        cache_flush_response_model_json['flushed'] = ['iam_cache']

        # Construct a model instance of CacheFlushResponse by calling from_dict on the json representation
        cache_flush_response_model = CacheFlushResponse.from_dict(cache_flush_response_model_json)
        assert cache_flush_response_model != False

        # Construct a model instance of CacheFlushResponse by calling from_dict on the json representation
        cache_flush_response_model_dict = CacheFlushResponse.from_dict(cache_flush_response_model_json).__dict__
        cache_flush_response_model2 = CacheFlushResponse(**cache_flush_response_model_dict)

        # Verify the model instances are equivalent
        assert cache_flush_response_model == cache_flush_response_model2

        # Convert model instance back to dict and verify no loss of data
        cache_flush_response_model_json2 = cache_flush_response_model.to_dict()
        assert cache_flush_response_model_json2 == cache_flush_response_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACfgIdentities
#-----------------------------------------------------------------------------
class TestConfigCACfgIdentities():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACfgIdentities
    #--------------------------------------------------------
    def test_config_ca_cfg_identities_serialization(self):

        # Construct a json representation of a ConfigCACfgIdentities model
        config_ca_cfg_identities_model_json = {}
        config_ca_cfg_identities_model_json['passwordattempts'] = 10
        config_ca_cfg_identities_model_json['allowremove'] = False

        # Construct a model instance of ConfigCACfgIdentities by calling from_dict on the json representation
        config_ca_cfg_identities_model = ConfigCACfgIdentities.from_dict(config_ca_cfg_identities_model_json)
        assert config_ca_cfg_identities_model != False

        # Construct a model instance of ConfigCACfgIdentities by calling from_dict on the json representation
        config_ca_cfg_identities_model_dict = ConfigCACfgIdentities.from_dict(config_ca_cfg_identities_model_json).__dict__
        config_ca_cfg_identities_model2 = ConfigCACfgIdentities(**config_ca_cfg_identities_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_cfg_identities_model == config_ca_cfg_identities_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_cfg_identities_model_json2 = config_ca_cfg_identities_model.to_dict()
        assert config_ca_cfg_identities_model_json2 == config_ca_cfg_identities_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACreate
#-----------------------------------------------------------------------------
class TestConfigCACreate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACreate
    #--------------------------------------------------------
    def test_config_ca_create_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_signing_profiles_ca_caconstraint_model = {} # ConfigCASigningProfilesCaCaconstraint
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        config_ca_db_tls_client_model = {} # ConfigCADbTlsClient
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        config_ca_intermediate_tls_client_model = {} # ConfigCAIntermediateTlsClient
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        config_ca_signing_profiles_ca_model = {} # ConfigCASigningProfilesCa
        config_ca_signing_profiles_ca_model['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        config_ca_signing_profiles_tls_model = {} # ConfigCASigningProfilesTls
        config_ca_signing_profiles_tls_model['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model['expiry'] = '43800h'

        identity_attrs_model = {} # IdentityAttrs
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        config_ca_cfg_identities_model = {} # ConfigCACfgIdentities
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        config_ca_csr_ca_model = {} # ConfigCACsrCa
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        config_ca_csr_keyrequest_model = {} # ConfigCACsrKeyrequest
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        config_ca_csr_names_item_model = {} # ConfigCACsrNamesItem
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        config_ca_db_tls_model = {} # ConfigCADbTls
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        config_ca_intermediate_enrollment_model = {} # ConfigCAIntermediateEnrollment
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        config_ca_intermediate_parentserver_model = {} # ConfigCAIntermediateParentserver
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        config_ca_intermediate_tls_model = {} # ConfigCAIntermediateTls
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        config_ca_registry_identities_item_model = {} # ConfigCARegistryIdentitiesItem
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        config_ca_signing_default_model = {} # ConfigCASigningDefault
        config_ca_signing_default_model['usage'] = ['cert sign']
        config_ca_signing_default_model['expiry'] = '8760h'

        config_ca_signing_profiles_model = {} # ConfigCASigningProfiles
        config_ca_signing_profiles_model['ca'] = config_ca_signing_profiles_ca_model
        config_ca_signing_profiles_model['tls'] = config_ca_signing_profiles_tls_model

        config_ca_tls_clientauth_model = {} # ConfigCATlsClientauth
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_ca_affiliations_model = {} # ConfigCAAffiliations
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        config_ca_ca_model = {} # ConfigCACa
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        config_ca_cfg_model = {} # ConfigCACfg
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        config_ca_cors_model = {} # ConfigCACors
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        config_ca_crl_model = {} # ConfigCACrl
        config_ca_crl_model['expiry'] = '24h'

        config_ca_csr_model = {} # ConfigCACsr
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        config_ca_db_model = {} # ConfigCADb
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        config_ca_idemix_model = {} # ConfigCAIdemix
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        config_ca_intermediate_model = {} # ConfigCAIntermediate
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        config_ca_registry_model = {} # ConfigCARegistry
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        config_ca_signing_model = {} # ConfigCASigning
        config_ca_signing_model['default'] = config_ca_signing_default_model
        config_ca_signing_model['profiles'] = config_ca_signing_profiles_model

        config_ca_tls_model = {} # ConfigCATls
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        metrics_model = {} # Metrics
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a json representation of a ConfigCACreate model
        config_ca_create_model_json = {}
        config_ca_create_model_json['cors'] = config_ca_cors_model
        config_ca_create_model_json['debug'] = False
        config_ca_create_model_json['crlsizelimit'] = 512000
        config_ca_create_model_json['tls'] = config_ca_tls_model
        config_ca_create_model_json['ca'] = config_ca_ca_model
        config_ca_create_model_json['crl'] = config_ca_crl_model
        config_ca_create_model_json['registry'] = config_ca_registry_model
        config_ca_create_model_json['db'] = config_ca_db_model
        config_ca_create_model_json['affiliations'] = config_ca_affiliations_model
        config_ca_create_model_json['csr'] = config_ca_csr_model
        config_ca_create_model_json['idemix'] = config_ca_idemix_model
        config_ca_create_model_json['BCCSP'] = bccsp_model
        config_ca_create_model_json['intermediate'] = config_ca_intermediate_model
        config_ca_create_model_json['cfg'] = config_ca_cfg_model
        config_ca_create_model_json['metrics'] = metrics_model
        config_ca_create_model_json['signing'] = config_ca_signing_model

        # Construct a model instance of ConfigCACreate by calling from_dict on the json representation
        config_ca_create_model = ConfigCACreate.from_dict(config_ca_create_model_json)
        assert config_ca_create_model != False

        # Construct a model instance of ConfigCACreate by calling from_dict on the json representation
        config_ca_create_model_dict = ConfigCACreate.from_dict(config_ca_create_model_json).__dict__
        config_ca_create_model2 = ConfigCACreate(**config_ca_create_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_create_model == config_ca_create_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_create_model_json2 = config_ca_create_model.to_dict()
        assert config_ca_create_model_json2 == config_ca_create_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACsrCa
#-----------------------------------------------------------------------------
class TestConfigCACsrCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACsrCa
    #--------------------------------------------------------
    def test_config_ca_csr_ca_serialization(self):

        # Construct a json representation of a ConfigCACsrCa model
        config_ca_csr_ca_model_json = {}
        config_ca_csr_ca_model_json['expiry'] = '131400h'
        config_ca_csr_ca_model_json['pathlength'] = 0

        # Construct a model instance of ConfigCACsrCa by calling from_dict on the json representation
        config_ca_csr_ca_model = ConfigCACsrCa.from_dict(config_ca_csr_ca_model_json)
        assert config_ca_csr_ca_model != False

        # Construct a model instance of ConfigCACsrCa by calling from_dict on the json representation
        config_ca_csr_ca_model_dict = ConfigCACsrCa.from_dict(config_ca_csr_ca_model_json).__dict__
        config_ca_csr_ca_model2 = ConfigCACsrCa(**config_ca_csr_ca_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_csr_ca_model == config_ca_csr_ca_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_csr_ca_model_json2 = config_ca_csr_ca_model.to_dict()
        assert config_ca_csr_ca_model_json2 == config_ca_csr_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACsrKeyrequest
#-----------------------------------------------------------------------------
class TestConfigCACsrKeyrequest():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACsrKeyrequest
    #--------------------------------------------------------
    def test_config_ca_csr_keyrequest_serialization(self):

        # Construct a json representation of a ConfigCACsrKeyrequest model
        config_ca_csr_keyrequest_model_json = {}
        config_ca_csr_keyrequest_model_json['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model_json['size'] = 256

        # Construct a model instance of ConfigCACsrKeyrequest by calling from_dict on the json representation
        config_ca_csr_keyrequest_model = ConfigCACsrKeyrequest.from_dict(config_ca_csr_keyrequest_model_json)
        assert config_ca_csr_keyrequest_model != False

        # Construct a model instance of ConfigCACsrKeyrequest by calling from_dict on the json representation
        config_ca_csr_keyrequest_model_dict = ConfigCACsrKeyrequest.from_dict(config_ca_csr_keyrequest_model_json).__dict__
        config_ca_csr_keyrequest_model2 = ConfigCACsrKeyrequest(**config_ca_csr_keyrequest_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_csr_keyrequest_model == config_ca_csr_keyrequest_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_csr_keyrequest_model_json2 = config_ca_csr_keyrequest_model.to_dict()
        assert config_ca_csr_keyrequest_model_json2 == config_ca_csr_keyrequest_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACsrNamesItem
#-----------------------------------------------------------------------------
class TestConfigCACsrNamesItem():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACsrNamesItem
    #--------------------------------------------------------
    def test_config_ca_csr_names_item_serialization(self):

        # Construct a json representation of a ConfigCACsrNamesItem model
        config_ca_csr_names_item_model_json = {}
        config_ca_csr_names_item_model_json['C'] = 'US'
        config_ca_csr_names_item_model_json['ST'] = 'North Carolina'
        config_ca_csr_names_item_model_json['L'] = 'Raleigh'
        config_ca_csr_names_item_model_json['O'] = 'Hyperledger'
        config_ca_csr_names_item_model_json['OU'] = 'Fabric'

        # Construct a model instance of ConfigCACsrNamesItem by calling from_dict on the json representation
        config_ca_csr_names_item_model = ConfigCACsrNamesItem.from_dict(config_ca_csr_names_item_model_json)
        assert config_ca_csr_names_item_model != False

        # Construct a model instance of ConfigCACsrNamesItem by calling from_dict on the json representation
        config_ca_csr_names_item_model_dict = ConfigCACsrNamesItem.from_dict(config_ca_csr_names_item_model_json).__dict__
        config_ca_csr_names_item_model2 = ConfigCACsrNamesItem(**config_ca_csr_names_item_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_csr_names_item_model == config_ca_csr_names_item_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_csr_names_item_model_json2 = config_ca_csr_names_item_model.to_dict()
        assert config_ca_csr_names_item_model_json2 == config_ca_csr_names_item_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCADbTls
#-----------------------------------------------------------------------------
class TestConfigCADbTls():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCADbTls
    #--------------------------------------------------------
    def test_config_ca_db_tls_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_db_tls_client_model = {} # ConfigCADbTlsClient
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        # Construct a json representation of a ConfigCADbTls model
        config_ca_db_tls_model_json = {}
        config_ca_db_tls_model_json['certfiles'] = ['testString']
        config_ca_db_tls_model_json['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model_json['enabled'] = False

        # Construct a model instance of ConfigCADbTls by calling from_dict on the json representation
        config_ca_db_tls_model = ConfigCADbTls.from_dict(config_ca_db_tls_model_json)
        assert config_ca_db_tls_model != False

        # Construct a model instance of ConfigCADbTls by calling from_dict on the json representation
        config_ca_db_tls_model_dict = ConfigCADbTls.from_dict(config_ca_db_tls_model_json).__dict__
        config_ca_db_tls_model2 = ConfigCADbTls(**config_ca_db_tls_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_db_tls_model == config_ca_db_tls_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_db_tls_model_json2 = config_ca_db_tls_model.to_dict()
        assert config_ca_db_tls_model_json2 == config_ca_db_tls_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCADbTlsClient
#-----------------------------------------------------------------------------
class TestConfigCADbTlsClient():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCADbTlsClient
    #--------------------------------------------------------
    def test_config_ca_db_tls_client_serialization(self):

        # Construct a json representation of a ConfigCADbTlsClient model
        config_ca_db_tls_client_model_json = {}
        config_ca_db_tls_client_model_json['certfile'] = 'testString'
        config_ca_db_tls_client_model_json['keyfile'] = 'testString'

        # Construct a model instance of ConfigCADbTlsClient by calling from_dict on the json representation
        config_ca_db_tls_client_model = ConfigCADbTlsClient.from_dict(config_ca_db_tls_client_model_json)
        assert config_ca_db_tls_client_model != False

        # Construct a model instance of ConfigCADbTlsClient by calling from_dict on the json representation
        config_ca_db_tls_client_model_dict = ConfigCADbTlsClient.from_dict(config_ca_db_tls_client_model_json).__dict__
        config_ca_db_tls_client_model2 = ConfigCADbTlsClient(**config_ca_db_tls_client_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_db_tls_client_model == config_ca_db_tls_client_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_db_tls_client_model_json2 = config_ca_db_tls_client_model.to_dict()
        assert config_ca_db_tls_client_model_json2 == config_ca_db_tls_client_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAIntermediateEnrollment
#-----------------------------------------------------------------------------
class TestConfigCAIntermediateEnrollment():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAIntermediateEnrollment
    #--------------------------------------------------------
    def test_config_ca_intermediate_enrollment_serialization(self):

        # Construct a json representation of a ConfigCAIntermediateEnrollment model
        config_ca_intermediate_enrollment_model_json = {}
        config_ca_intermediate_enrollment_model_json['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model_json['profile'] = 'testString'
        config_ca_intermediate_enrollment_model_json['label'] = 'testString'

        # Construct a model instance of ConfigCAIntermediateEnrollment by calling from_dict on the json representation
        config_ca_intermediate_enrollment_model = ConfigCAIntermediateEnrollment.from_dict(config_ca_intermediate_enrollment_model_json)
        assert config_ca_intermediate_enrollment_model != False

        # Construct a model instance of ConfigCAIntermediateEnrollment by calling from_dict on the json representation
        config_ca_intermediate_enrollment_model_dict = ConfigCAIntermediateEnrollment.from_dict(config_ca_intermediate_enrollment_model_json).__dict__
        config_ca_intermediate_enrollment_model2 = ConfigCAIntermediateEnrollment(**config_ca_intermediate_enrollment_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_intermediate_enrollment_model == config_ca_intermediate_enrollment_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_intermediate_enrollment_model_json2 = config_ca_intermediate_enrollment_model.to_dict()
        assert config_ca_intermediate_enrollment_model_json2 == config_ca_intermediate_enrollment_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAIntermediateParentserver
#-----------------------------------------------------------------------------
class TestConfigCAIntermediateParentserver():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAIntermediateParentserver
    #--------------------------------------------------------
    def test_config_ca_intermediate_parentserver_serialization(self):

        # Construct a json representation of a ConfigCAIntermediateParentserver model
        config_ca_intermediate_parentserver_model_json = {}
        config_ca_intermediate_parentserver_model_json['url'] = 'testString'
        config_ca_intermediate_parentserver_model_json['caname'] = 'testString'

        # Construct a model instance of ConfigCAIntermediateParentserver by calling from_dict on the json representation
        config_ca_intermediate_parentserver_model = ConfigCAIntermediateParentserver.from_dict(config_ca_intermediate_parentserver_model_json)
        assert config_ca_intermediate_parentserver_model != False

        # Construct a model instance of ConfigCAIntermediateParentserver by calling from_dict on the json representation
        config_ca_intermediate_parentserver_model_dict = ConfigCAIntermediateParentserver.from_dict(config_ca_intermediate_parentserver_model_json).__dict__
        config_ca_intermediate_parentserver_model2 = ConfigCAIntermediateParentserver(**config_ca_intermediate_parentserver_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_intermediate_parentserver_model == config_ca_intermediate_parentserver_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_intermediate_parentserver_model_json2 = config_ca_intermediate_parentserver_model.to_dict()
        assert config_ca_intermediate_parentserver_model_json2 == config_ca_intermediate_parentserver_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAIntermediateTls
#-----------------------------------------------------------------------------
class TestConfigCAIntermediateTls():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAIntermediateTls
    #--------------------------------------------------------
    def test_config_ca_intermediate_tls_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_intermediate_tls_client_model = {} # ConfigCAIntermediateTlsClient
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        # Construct a json representation of a ConfigCAIntermediateTls model
        config_ca_intermediate_tls_model_json = {}
        config_ca_intermediate_tls_model_json['certfiles'] = ['testString']
        config_ca_intermediate_tls_model_json['client'] = config_ca_intermediate_tls_client_model

        # Construct a model instance of ConfigCAIntermediateTls by calling from_dict on the json representation
        config_ca_intermediate_tls_model = ConfigCAIntermediateTls.from_dict(config_ca_intermediate_tls_model_json)
        assert config_ca_intermediate_tls_model != False

        # Construct a model instance of ConfigCAIntermediateTls by calling from_dict on the json representation
        config_ca_intermediate_tls_model_dict = ConfigCAIntermediateTls.from_dict(config_ca_intermediate_tls_model_json).__dict__
        config_ca_intermediate_tls_model2 = ConfigCAIntermediateTls(**config_ca_intermediate_tls_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_intermediate_tls_model == config_ca_intermediate_tls_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_intermediate_tls_model_json2 = config_ca_intermediate_tls_model.to_dict()
        assert config_ca_intermediate_tls_model_json2 == config_ca_intermediate_tls_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAIntermediateTlsClient
#-----------------------------------------------------------------------------
class TestConfigCAIntermediateTlsClient():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAIntermediateTlsClient
    #--------------------------------------------------------
    def test_config_ca_intermediate_tls_client_serialization(self):

        # Construct a json representation of a ConfigCAIntermediateTlsClient model
        config_ca_intermediate_tls_client_model_json = {}
        config_ca_intermediate_tls_client_model_json['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model_json['keyfile'] = 'testString'

        # Construct a model instance of ConfigCAIntermediateTlsClient by calling from_dict on the json representation
        config_ca_intermediate_tls_client_model = ConfigCAIntermediateTlsClient.from_dict(config_ca_intermediate_tls_client_model_json)
        assert config_ca_intermediate_tls_client_model != False

        # Construct a model instance of ConfigCAIntermediateTlsClient by calling from_dict on the json representation
        config_ca_intermediate_tls_client_model_dict = ConfigCAIntermediateTlsClient.from_dict(config_ca_intermediate_tls_client_model_json).__dict__
        config_ca_intermediate_tls_client_model2 = ConfigCAIntermediateTlsClient(**config_ca_intermediate_tls_client_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_intermediate_tls_client_model == config_ca_intermediate_tls_client_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_intermediate_tls_client_model_json2 = config_ca_intermediate_tls_client_model.to_dict()
        assert config_ca_intermediate_tls_client_model_json2 == config_ca_intermediate_tls_client_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCARegistryIdentitiesItem
#-----------------------------------------------------------------------------
class TestConfigCARegistryIdentitiesItem():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCARegistryIdentitiesItem
    #--------------------------------------------------------
    def test_config_ca_registry_identities_item_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        identity_attrs_model = {} # IdentityAttrs
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        # Construct a json representation of a ConfigCARegistryIdentitiesItem model
        config_ca_registry_identities_item_model_json = {}
        config_ca_registry_identities_item_model_json['name'] = 'admin'
        config_ca_registry_identities_item_model_json['pass'] = 'password'
        config_ca_registry_identities_item_model_json['type'] = 'client'
        config_ca_registry_identities_item_model_json['maxenrollments'] = -1
        config_ca_registry_identities_item_model_json['affiliation'] = 'testString'
        config_ca_registry_identities_item_model_json['attrs'] = identity_attrs_model

        # Construct a model instance of ConfigCARegistryIdentitiesItem by calling from_dict on the json representation
        config_ca_registry_identities_item_model = ConfigCARegistryIdentitiesItem.from_dict(config_ca_registry_identities_item_model_json)
        assert config_ca_registry_identities_item_model != False

        # Construct a model instance of ConfigCARegistryIdentitiesItem by calling from_dict on the json representation
        config_ca_registry_identities_item_model_dict = ConfigCARegistryIdentitiesItem.from_dict(config_ca_registry_identities_item_model_json).__dict__
        config_ca_registry_identities_item_model2 = ConfigCARegistryIdentitiesItem(**config_ca_registry_identities_item_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_registry_identities_item_model == config_ca_registry_identities_item_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_registry_identities_item_model_json2 = config_ca_registry_identities_item_model.to_dict()
        assert config_ca_registry_identities_item_model_json2 == config_ca_registry_identities_item_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCASigningDefault
#-----------------------------------------------------------------------------
class TestConfigCASigningDefault():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCASigningDefault
    #--------------------------------------------------------
    def test_config_ca_signing_default_serialization(self):

        # Construct a json representation of a ConfigCASigningDefault model
        config_ca_signing_default_model_json = {}
        config_ca_signing_default_model_json['usage'] = ['cert sign']
        config_ca_signing_default_model_json['expiry'] = '8760h'

        # Construct a model instance of ConfigCASigningDefault by calling from_dict on the json representation
        config_ca_signing_default_model = ConfigCASigningDefault.from_dict(config_ca_signing_default_model_json)
        assert config_ca_signing_default_model != False

        # Construct a model instance of ConfigCASigningDefault by calling from_dict on the json representation
        config_ca_signing_default_model_dict = ConfigCASigningDefault.from_dict(config_ca_signing_default_model_json).__dict__
        config_ca_signing_default_model2 = ConfigCASigningDefault(**config_ca_signing_default_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_signing_default_model == config_ca_signing_default_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_signing_default_model_json2 = config_ca_signing_default_model.to_dict()
        assert config_ca_signing_default_model_json2 == config_ca_signing_default_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCASigningProfiles
#-----------------------------------------------------------------------------
class TestConfigCASigningProfiles():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCASigningProfiles
    #--------------------------------------------------------
    def test_config_ca_signing_profiles_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_signing_profiles_ca_caconstraint_model = {} # ConfigCASigningProfilesCaCaconstraint
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        config_ca_signing_profiles_ca_model = {} # ConfigCASigningProfilesCa
        config_ca_signing_profiles_ca_model['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        config_ca_signing_profiles_tls_model = {} # ConfigCASigningProfilesTls
        config_ca_signing_profiles_tls_model['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model['expiry'] = '43800h'

        # Construct a json representation of a ConfigCASigningProfiles model
        config_ca_signing_profiles_model_json = {}
        config_ca_signing_profiles_model_json['ca'] = config_ca_signing_profiles_ca_model
        config_ca_signing_profiles_model_json['tls'] = config_ca_signing_profiles_tls_model

        # Construct a model instance of ConfigCASigningProfiles by calling from_dict on the json representation
        config_ca_signing_profiles_model = ConfigCASigningProfiles.from_dict(config_ca_signing_profiles_model_json)
        assert config_ca_signing_profiles_model != False

        # Construct a model instance of ConfigCASigningProfiles by calling from_dict on the json representation
        config_ca_signing_profiles_model_dict = ConfigCASigningProfiles.from_dict(config_ca_signing_profiles_model_json).__dict__
        config_ca_signing_profiles_model2 = ConfigCASigningProfiles(**config_ca_signing_profiles_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_signing_profiles_model == config_ca_signing_profiles_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_signing_profiles_model_json2 = config_ca_signing_profiles_model.to_dict()
        assert config_ca_signing_profiles_model_json2 == config_ca_signing_profiles_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCASigningProfilesCa
#-----------------------------------------------------------------------------
class TestConfigCASigningProfilesCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCASigningProfilesCa
    #--------------------------------------------------------
    def test_config_ca_signing_profiles_ca_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_signing_profiles_ca_caconstraint_model = {} # ConfigCASigningProfilesCaCaconstraint
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        # Construct a json representation of a ConfigCASigningProfilesCa model
        config_ca_signing_profiles_ca_model_json = {}
        config_ca_signing_profiles_ca_model_json['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model_json['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model_json['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        # Construct a model instance of ConfigCASigningProfilesCa by calling from_dict on the json representation
        config_ca_signing_profiles_ca_model = ConfigCASigningProfilesCa.from_dict(config_ca_signing_profiles_ca_model_json)
        assert config_ca_signing_profiles_ca_model != False

        # Construct a model instance of ConfigCASigningProfilesCa by calling from_dict on the json representation
        config_ca_signing_profiles_ca_model_dict = ConfigCASigningProfilesCa.from_dict(config_ca_signing_profiles_ca_model_json).__dict__
        config_ca_signing_profiles_ca_model2 = ConfigCASigningProfilesCa(**config_ca_signing_profiles_ca_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_signing_profiles_ca_model == config_ca_signing_profiles_ca_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_signing_profiles_ca_model_json2 = config_ca_signing_profiles_ca_model.to_dict()
        assert config_ca_signing_profiles_ca_model_json2 == config_ca_signing_profiles_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCASigningProfilesCaCaconstraint
#-----------------------------------------------------------------------------
class TestConfigCASigningProfilesCaCaconstraint():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCASigningProfilesCaCaconstraint
    #--------------------------------------------------------
    def test_config_ca_signing_profiles_ca_caconstraint_serialization(self):

        # Construct a json representation of a ConfigCASigningProfilesCaCaconstraint model
        config_ca_signing_profiles_ca_caconstraint_model_json = {}
        config_ca_signing_profiles_ca_caconstraint_model_json['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model_json['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model_json['maxpathlenzero'] = True

        # Construct a model instance of ConfigCASigningProfilesCaCaconstraint by calling from_dict on the json representation
        config_ca_signing_profiles_ca_caconstraint_model = ConfigCASigningProfilesCaCaconstraint.from_dict(config_ca_signing_profiles_ca_caconstraint_model_json)
        assert config_ca_signing_profiles_ca_caconstraint_model != False

        # Construct a model instance of ConfigCASigningProfilesCaCaconstraint by calling from_dict on the json representation
        config_ca_signing_profiles_ca_caconstraint_model_dict = ConfigCASigningProfilesCaCaconstraint.from_dict(config_ca_signing_profiles_ca_caconstraint_model_json).__dict__
        config_ca_signing_profiles_ca_caconstraint_model2 = ConfigCASigningProfilesCaCaconstraint(**config_ca_signing_profiles_ca_caconstraint_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_signing_profiles_ca_caconstraint_model == config_ca_signing_profiles_ca_caconstraint_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_signing_profiles_ca_caconstraint_model_json2 = config_ca_signing_profiles_ca_caconstraint_model.to_dict()
        assert config_ca_signing_profiles_ca_caconstraint_model_json2 == config_ca_signing_profiles_ca_caconstraint_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCASigningProfilesTls
#-----------------------------------------------------------------------------
class TestConfigCASigningProfilesTls():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCASigningProfilesTls
    #--------------------------------------------------------
    def test_config_ca_signing_profiles_tls_serialization(self):

        # Construct a json representation of a ConfigCASigningProfilesTls model
        config_ca_signing_profiles_tls_model_json = {}
        config_ca_signing_profiles_tls_model_json['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model_json['expiry'] = '43800h'

        # Construct a model instance of ConfigCASigningProfilesTls by calling from_dict on the json representation
        config_ca_signing_profiles_tls_model = ConfigCASigningProfilesTls.from_dict(config_ca_signing_profiles_tls_model_json)
        assert config_ca_signing_profiles_tls_model != False

        # Construct a model instance of ConfigCASigningProfilesTls by calling from_dict on the json representation
        config_ca_signing_profiles_tls_model_dict = ConfigCASigningProfilesTls.from_dict(config_ca_signing_profiles_tls_model_json).__dict__
        config_ca_signing_profiles_tls_model2 = ConfigCASigningProfilesTls(**config_ca_signing_profiles_tls_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_signing_profiles_tls_model == config_ca_signing_profiles_tls_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_signing_profiles_tls_model_json2 = config_ca_signing_profiles_tls_model.to_dict()
        assert config_ca_signing_profiles_tls_model_json2 == config_ca_signing_profiles_tls_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCATlsClientauth
#-----------------------------------------------------------------------------
class TestConfigCATlsClientauth():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCATlsClientauth
    #--------------------------------------------------------
    def test_config_ca_tls_clientauth_serialization(self):

        # Construct a json representation of a ConfigCATlsClientauth model
        config_ca_tls_clientauth_model_json = {}
        config_ca_tls_clientauth_model_json['type'] = 'noclientcert'
        config_ca_tls_clientauth_model_json['certfiles'] = ['testString']

        # Construct a model instance of ConfigCATlsClientauth by calling from_dict on the json representation
        config_ca_tls_clientauth_model = ConfigCATlsClientauth.from_dict(config_ca_tls_clientauth_model_json)
        assert config_ca_tls_clientauth_model != False

        # Construct a model instance of ConfigCATlsClientauth by calling from_dict on the json representation
        config_ca_tls_clientauth_model_dict = ConfigCATlsClientauth.from_dict(config_ca_tls_clientauth_model_json).__dict__
        config_ca_tls_clientauth_model2 = ConfigCATlsClientauth(**config_ca_tls_clientauth_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_tls_clientauth_model == config_ca_tls_clientauth_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_tls_clientauth_model_json2 = config_ca_tls_clientauth_model.to_dict()
        assert config_ca_tls_clientauth_model_json2 == config_ca_tls_clientauth_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAUpdate
#-----------------------------------------------------------------------------
class TestConfigCAUpdate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAUpdate
    #--------------------------------------------------------
    def test_config_ca_update_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_db_tls_client_model = {} # ConfigCADbTlsClient
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        config_ca_intermediate_tls_client_model = {} # ConfigCAIntermediateTlsClient
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        identity_attrs_model = {} # IdentityAttrs
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        config_ca_cfg_identities_model = {} # ConfigCACfgIdentities
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        config_ca_csr_ca_model = {} # ConfigCACsrCa
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        config_ca_csr_keyrequest_model = {} # ConfigCACsrKeyrequest
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        config_ca_csr_names_item_model = {} # ConfigCACsrNamesItem
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        config_ca_db_tls_model = {} # ConfigCADbTls
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        config_ca_intermediate_enrollment_model = {} # ConfigCAIntermediateEnrollment
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        config_ca_intermediate_parentserver_model = {} # ConfigCAIntermediateParentserver
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        config_ca_intermediate_tls_model = {} # ConfigCAIntermediateTls
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        config_ca_registry_identities_item_model = {} # ConfigCARegistryIdentitiesItem
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        config_ca_tls_clientauth_model = {} # ConfigCATlsClientauth
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_ca_affiliations_model = {} # ConfigCAAffiliations
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        config_ca_ca_model = {} # ConfigCACa
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        config_ca_cfg_model = {} # ConfigCACfg
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        config_ca_cors_model = {} # ConfigCACors
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        config_ca_crl_model = {} # ConfigCACrl
        config_ca_crl_model['expiry'] = '24h'

        config_ca_csr_model = {} # ConfigCACsr
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        config_ca_db_model = {} # ConfigCADb
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        config_ca_idemix_model = {} # ConfigCAIdemix
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        config_ca_intermediate_model = {} # ConfigCAIntermediate
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        config_ca_registry_model = {} # ConfigCARegistry
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        config_ca_tls_model = {} # ConfigCATls
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        metrics_model = {} # Metrics
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a json representation of a ConfigCAUpdate model
        config_ca_update_model_json = {}
        config_ca_update_model_json['cors'] = config_ca_cors_model
        config_ca_update_model_json['debug'] = False
        config_ca_update_model_json['crlsizelimit'] = 512000
        config_ca_update_model_json['tls'] = config_ca_tls_model
        config_ca_update_model_json['ca'] = config_ca_ca_model
        config_ca_update_model_json['crl'] = config_ca_crl_model
        config_ca_update_model_json['registry'] = config_ca_registry_model
        config_ca_update_model_json['db'] = config_ca_db_model
        config_ca_update_model_json['affiliations'] = config_ca_affiliations_model
        config_ca_update_model_json['csr'] = config_ca_csr_model
        config_ca_update_model_json['idemix'] = config_ca_idemix_model
        config_ca_update_model_json['BCCSP'] = bccsp_model
        config_ca_update_model_json['intermediate'] = config_ca_intermediate_model
        config_ca_update_model_json['cfg'] = config_ca_cfg_model
        config_ca_update_model_json['metrics'] = metrics_model

        # Construct a model instance of ConfigCAUpdate by calling from_dict on the json representation
        config_ca_update_model = ConfigCAUpdate.from_dict(config_ca_update_model_json)
        assert config_ca_update_model != False

        # Construct a model instance of ConfigCAUpdate by calling from_dict on the json representation
        config_ca_update_model_dict = ConfigCAUpdate.from_dict(config_ca_update_model_json).__dict__
        config_ca_update_model2 = ConfigCAUpdate(**config_ca_update_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_update_model == config_ca_update_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_update_model_json2 = config_ca_update_model.to_dict()
        assert config_ca_update_model_json2 == config_ca_update_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAAffiliations
#-----------------------------------------------------------------------------
class TestConfigCAAffiliations():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAAffiliations
    #--------------------------------------------------------
    def test_config_ca_affiliations_serialization(self):

        # Construct a json representation of a ConfigCAAffiliations model
        config_ca_affiliations_model_json = {}
        config_ca_affiliations_model_json['org1'] = ['department1']
        config_ca_affiliations_model_json['org2'] = ['department1']
        config_ca_affiliations_model_json['foo'] = { 'foo': 'bar' }

        # Construct a model instance of ConfigCAAffiliations by calling from_dict on the json representation
        config_ca_affiliations_model = ConfigCAAffiliations.from_dict(config_ca_affiliations_model_json)
        assert config_ca_affiliations_model != False

        # Construct a model instance of ConfigCAAffiliations by calling from_dict on the json representation
        config_ca_affiliations_model_dict = ConfigCAAffiliations.from_dict(config_ca_affiliations_model_json).__dict__
        config_ca_affiliations_model2 = ConfigCAAffiliations(**config_ca_affiliations_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_affiliations_model == config_ca_affiliations_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_affiliations_model_json2 = config_ca_affiliations_model.to_dict()
        assert config_ca_affiliations_model_json2 == config_ca_affiliations_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACa
#-----------------------------------------------------------------------------
class TestConfigCACa():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACa
    #--------------------------------------------------------
    def test_config_ca_ca_serialization(self):

        # Construct a json representation of a ConfigCACa model
        config_ca_ca_model_json = {}
        config_ca_ca_model_json['keyfile'] = 'testString'
        config_ca_ca_model_json['certfile'] = 'testString'
        config_ca_ca_model_json['chainfile'] = 'testString'

        # Construct a model instance of ConfigCACa by calling from_dict on the json representation
        config_ca_ca_model = ConfigCACa.from_dict(config_ca_ca_model_json)
        assert config_ca_ca_model != False

        # Construct a model instance of ConfigCACa by calling from_dict on the json representation
        config_ca_ca_model_dict = ConfigCACa.from_dict(config_ca_ca_model_json).__dict__
        config_ca_ca_model2 = ConfigCACa(**config_ca_ca_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_ca_model == config_ca_ca_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_ca_model_json2 = config_ca_ca_model.to_dict()
        assert config_ca_ca_model_json2 == config_ca_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACfg
#-----------------------------------------------------------------------------
class TestConfigCACfg():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACfg
    #--------------------------------------------------------
    def test_config_ca_cfg_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_cfg_identities_model = {} # ConfigCACfgIdentities
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        # Construct a json representation of a ConfigCACfg model
        config_ca_cfg_model_json = {}
        config_ca_cfg_model_json['identities'] = config_ca_cfg_identities_model

        # Construct a model instance of ConfigCACfg by calling from_dict on the json representation
        config_ca_cfg_model = ConfigCACfg.from_dict(config_ca_cfg_model_json)
        assert config_ca_cfg_model != False

        # Construct a model instance of ConfigCACfg by calling from_dict on the json representation
        config_ca_cfg_model_dict = ConfigCACfg.from_dict(config_ca_cfg_model_json).__dict__
        config_ca_cfg_model2 = ConfigCACfg(**config_ca_cfg_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_cfg_model == config_ca_cfg_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_cfg_model_json2 = config_ca_cfg_model.to_dict()
        assert config_ca_cfg_model_json2 == config_ca_cfg_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACors
#-----------------------------------------------------------------------------
class TestConfigCACors():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACors
    #--------------------------------------------------------
    def test_config_ca_cors_serialization(self):

        # Construct a json representation of a ConfigCACors model
        config_ca_cors_model_json = {}
        config_ca_cors_model_json['enabled'] = True
        config_ca_cors_model_json['origins'] = ['*']

        # Construct a model instance of ConfigCACors by calling from_dict on the json representation
        config_ca_cors_model = ConfigCACors.from_dict(config_ca_cors_model_json)
        assert config_ca_cors_model != False

        # Construct a model instance of ConfigCACors by calling from_dict on the json representation
        config_ca_cors_model_dict = ConfigCACors.from_dict(config_ca_cors_model_json).__dict__
        config_ca_cors_model2 = ConfigCACors(**config_ca_cors_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_cors_model == config_ca_cors_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_cors_model_json2 = config_ca_cors_model.to_dict()
        assert config_ca_cors_model_json2 == config_ca_cors_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACrl
#-----------------------------------------------------------------------------
class TestConfigCACrl():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACrl
    #--------------------------------------------------------
    def test_config_ca_crl_serialization(self):

        # Construct a json representation of a ConfigCACrl model
        config_ca_crl_model_json = {}
        config_ca_crl_model_json['expiry'] = '24h'

        # Construct a model instance of ConfigCACrl by calling from_dict on the json representation
        config_ca_crl_model = ConfigCACrl.from_dict(config_ca_crl_model_json)
        assert config_ca_crl_model != False

        # Construct a model instance of ConfigCACrl by calling from_dict on the json representation
        config_ca_crl_model_dict = ConfigCACrl.from_dict(config_ca_crl_model_json).__dict__
        config_ca_crl_model2 = ConfigCACrl(**config_ca_crl_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_crl_model == config_ca_crl_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_crl_model_json2 = config_ca_crl_model.to_dict()
        assert config_ca_crl_model_json2 == config_ca_crl_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCACsr
#-----------------------------------------------------------------------------
class TestConfigCACsr():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCACsr
    #--------------------------------------------------------
    def test_config_ca_csr_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_csr_ca_model = {} # ConfigCACsrCa
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        config_ca_csr_keyrequest_model = {} # ConfigCACsrKeyrequest
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        config_ca_csr_names_item_model = {} # ConfigCACsrNamesItem
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        # Construct a json representation of a ConfigCACsr model
        config_ca_csr_model_json = {}
        config_ca_csr_model_json['cn'] = 'ca'
        config_ca_csr_model_json['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model_json['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model_json['hosts'] = ['localhost']
        config_ca_csr_model_json['ca'] = config_ca_csr_ca_model

        # Construct a model instance of ConfigCACsr by calling from_dict on the json representation
        config_ca_csr_model = ConfigCACsr.from_dict(config_ca_csr_model_json)
        assert config_ca_csr_model != False

        # Construct a model instance of ConfigCACsr by calling from_dict on the json representation
        config_ca_csr_model_dict = ConfigCACsr.from_dict(config_ca_csr_model_json).__dict__
        config_ca_csr_model2 = ConfigCACsr(**config_ca_csr_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_csr_model == config_ca_csr_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_csr_model_json2 = config_ca_csr_model.to_dict()
        assert config_ca_csr_model_json2 == config_ca_csr_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCADb
#-----------------------------------------------------------------------------
class TestConfigCADb():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCADb
    #--------------------------------------------------------
    def test_config_ca_db_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_db_tls_client_model = {} # ConfigCADbTlsClient
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        config_ca_db_tls_model = {} # ConfigCADbTls
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        # Construct a json representation of a ConfigCADb model
        config_ca_db_model_json = {}
        config_ca_db_model_json['type'] = 'postgres'
        config_ca_db_model_json['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model_json['tls'] = config_ca_db_tls_model

        # Construct a model instance of ConfigCADb by calling from_dict on the json representation
        config_ca_db_model = ConfigCADb.from_dict(config_ca_db_model_json)
        assert config_ca_db_model != False

        # Construct a model instance of ConfigCADb by calling from_dict on the json representation
        config_ca_db_model_dict = ConfigCADb.from_dict(config_ca_db_model_json).__dict__
        config_ca_db_model2 = ConfigCADb(**config_ca_db_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_db_model == config_ca_db_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_db_model_json2 = config_ca_db_model.to_dict()
        assert config_ca_db_model_json2 == config_ca_db_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAIdemix
#-----------------------------------------------------------------------------
class TestConfigCAIdemix():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAIdemix
    #--------------------------------------------------------
    def test_config_ca_idemix_serialization(self):

        # Construct a json representation of a ConfigCAIdemix model
        config_ca_idemix_model_json = {}
        config_ca_idemix_model_json['rhpoolsize'] = 100
        config_ca_idemix_model_json['nonceexpiration'] = '15s'
        config_ca_idemix_model_json['noncesweepinterval'] = '15m'

        # Construct a model instance of ConfigCAIdemix by calling from_dict on the json representation
        config_ca_idemix_model = ConfigCAIdemix.from_dict(config_ca_idemix_model_json)
        assert config_ca_idemix_model != False

        # Construct a model instance of ConfigCAIdemix by calling from_dict on the json representation
        config_ca_idemix_model_dict = ConfigCAIdemix.from_dict(config_ca_idemix_model_json).__dict__
        config_ca_idemix_model2 = ConfigCAIdemix(**config_ca_idemix_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_idemix_model == config_ca_idemix_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_idemix_model_json2 = config_ca_idemix_model.to_dict()
        assert config_ca_idemix_model_json2 == config_ca_idemix_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCAIntermediate
#-----------------------------------------------------------------------------
class TestConfigCAIntermediate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCAIntermediate
    #--------------------------------------------------------
    def test_config_ca_intermediate_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_intermediate_tls_client_model = {} # ConfigCAIntermediateTlsClient
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        config_ca_intermediate_enrollment_model = {} # ConfigCAIntermediateEnrollment
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        config_ca_intermediate_parentserver_model = {} # ConfigCAIntermediateParentserver
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        config_ca_intermediate_tls_model = {} # ConfigCAIntermediateTls
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        # Construct a json representation of a ConfigCAIntermediate model
        config_ca_intermediate_model_json = {}
        config_ca_intermediate_model_json['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model_json['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model_json['tls'] = config_ca_intermediate_tls_model

        # Construct a model instance of ConfigCAIntermediate by calling from_dict on the json representation
        config_ca_intermediate_model = ConfigCAIntermediate.from_dict(config_ca_intermediate_model_json)
        assert config_ca_intermediate_model != False

        # Construct a model instance of ConfigCAIntermediate by calling from_dict on the json representation
        config_ca_intermediate_model_dict = ConfigCAIntermediate.from_dict(config_ca_intermediate_model_json).__dict__
        config_ca_intermediate_model2 = ConfigCAIntermediate(**config_ca_intermediate_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_intermediate_model == config_ca_intermediate_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_intermediate_model_json2 = config_ca_intermediate_model.to_dict()
        assert config_ca_intermediate_model_json2 == config_ca_intermediate_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCARegistry
#-----------------------------------------------------------------------------
class TestConfigCARegistry():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCARegistry
    #--------------------------------------------------------
    def test_config_ca_registry_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        identity_attrs_model = {} # IdentityAttrs
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        config_ca_registry_identities_item_model = {} # ConfigCARegistryIdentitiesItem
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        # Construct a json representation of a ConfigCARegistry model
        config_ca_registry_model_json = {}
        config_ca_registry_model_json['maxenrollments'] = -1
        config_ca_registry_model_json['identities'] = [config_ca_registry_identities_item_model]

        # Construct a model instance of ConfigCARegistry by calling from_dict on the json representation
        config_ca_registry_model = ConfigCARegistry.from_dict(config_ca_registry_model_json)
        assert config_ca_registry_model != False

        # Construct a model instance of ConfigCARegistry by calling from_dict on the json representation
        config_ca_registry_model_dict = ConfigCARegistry.from_dict(config_ca_registry_model_json).__dict__
        config_ca_registry_model2 = ConfigCARegistry(**config_ca_registry_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_registry_model == config_ca_registry_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_registry_model_json2 = config_ca_registry_model.to_dict()
        assert config_ca_registry_model_json2 == config_ca_registry_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCASigning
#-----------------------------------------------------------------------------
class TestConfigCASigning():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCASigning
    #--------------------------------------------------------
    def test_config_ca_signing_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_signing_profiles_ca_caconstraint_model = {} # ConfigCASigningProfilesCaCaconstraint
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        config_ca_signing_profiles_ca_model = {} # ConfigCASigningProfilesCa
        config_ca_signing_profiles_ca_model['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        config_ca_signing_profiles_tls_model = {} # ConfigCASigningProfilesTls
        config_ca_signing_profiles_tls_model['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model['expiry'] = '43800h'

        config_ca_signing_default_model = {} # ConfigCASigningDefault
        config_ca_signing_default_model['usage'] = ['cert sign']
        config_ca_signing_default_model['expiry'] = '8760h'

        config_ca_signing_profiles_model = {} # ConfigCASigningProfiles
        config_ca_signing_profiles_model['ca'] = config_ca_signing_profiles_ca_model
        config_ca_signing_profiles_model['tls'] = config_ca_signing_profiles_tls_model

        # Construct a json representation of a ConfigCASigning model
        config_ca_signing_model_json = {}
        config_ca_signing_model_json['default'] = config_ca_signing_default_model
        config_ca_signing_model_json['profiles'] = config_ca_signing_profiles_model

        # Construct a model instance of ConfigCASigning by calling from_dict on the json representation
        config_ca_signing_model = ConfigCASigning.from_dict(config_ca_signing_model_json)
        assert config_ca_signing_model != False

        # Construct a model instance of ConfigCASigning by calling from_dict on the json representation
        config_ca_signing_model_dict = ConfigCASigning.from_dict(config_ca_signing_model_json).__dict__
        config_ca_signing_model2 = ConfigCASigning(**config_ca_signing_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_signing_model == config_ca_signing_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_signing_model_json2 = config_ca_signing_model.to_dict()
        assert config_ca_signing_model_json2 == config_ca_signing_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigCATls
#-----------------------------------------------------------------------------
class TestConfigCATls():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigCATls
    #--------------------------------------------------------
    def test_config_ca_tls_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_tls_clientauth_model = {} # ConfigCATlsClientauth
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        # Construct a json representation of a ConfigCATls model
        config_ca_tls_model_json = {}
        config_ca_tls_model_json['keyfile'] = 'testString'
        config_ca_tls_model_json['certfile'] = 'testString'
        config_ca_tls_model_json['clientauth'] = config_ca_tls_clientauth_model

        # Construct a model instance of ConfigCATls by calling from_dict on the json representation
        config_ca_tls_model = ConfigCATls.from_dict(config_ca_tls_model_json)
        assert config_ca_tls_model != False

        # Construct a model instance of ConfigCATls by calling from_dict on the json representation
        config_ca_tls_model_dict = ConfigCATls.from_dict(config_ca_tls_model_json).__dict__
        config_ca_tls_model2 = ConfigCATls(**config_ca_tls_model_dict)

        # Verify the model instances are equivalent
        assert config_ca_tls_model == config_ca_tls_model2

        # Convert model instance back to dict and verify no loss of data
        config_ca_tls_model_json2 = config_ca_tls_model.to_dict()
        assert config_ca_tls_model_json2 == config_ca_tls_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererCreate
#-----------------------------------------------------------------------------
class TestConfigOrdererCreate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererCreate
    #--------------------------------------------------------
    def test_config_orderer_create_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_orderer_authentication_model = {} # ConfigOrdererAuthentication
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        config_orderer_keepalive_model = {} # ConfigOrdererKeepalive
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        config_orderer_metrics_statsd_model = {} # ConfigOrdererMetricsStatsd
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        config_orderer_debug_model = {} # ConfigOrdererDebug
        config_orderer_debug_model['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model['DeliverTraceDir'] = 'testString'

        config_orderer_general_model = {} # ConfigOrdererGeneral
        config_orderer_general_model['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_model['BCCSP'] = bccsp_model
        config_orderer_general_model['Authentication'] = config_orderer_authentication_model

        config_orderer_metrics_model = {} # ConfigOrdererMetrics
        config_orderer_metrics_model['Provider'] = 'disabled'
        config_orderer_metrics_model['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a json representation of a ConfigOrdererCreate model
        config_orderer_create_model_json = {}
        config_orderer_create_model_json['General'] = config_orderer_general_model
        config_orderer_create_model_json['Debug'] = config_orderer_debug_model
        config_orderer_create_model_json['Metrics'] = config_orderer_metrics_model

        # Construct a model instance of ConfigOrdererCreate by calling from_dict on the json representation
        config_orderer_create_model = ConfigOrdererCreate.from_dict(config_orderer_create_model_json)
        assert config_orderer_create_model != False

        # Construct a model instance of ConfigOrdererCreate by calling from_dict on the json representation
        config_orderer_create_model_dict = ConfigOrdererCreate.from_dict(config_orderer_create_model_json).__dict__
        config_orderer_create_model2 = ConfigOrdererCreate(**config_orderer_create_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_create_model == config_orderer_create_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_create_model_json2 = config_orderer_create_model.to_dict()
        assert config_orderer_create_model_json2 == config_orderer_create_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererMetricsStatsd
#-----------------------------------------------------------------------------
class TestConfigOrdererMetricsStatsd():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererMetricsStatsd
    #--------------------------------------------------------
    def test_config_orderer_metrics_statsd_serialization(self):

        # Construct a json representation of a ConfigOrdererMetricsStatsd model
        config_orderer_metrics_statsd_model_json = {}
        config_orderer_metrics_statsd_model_json['Network'] = 'udp'
        config_orderer_metrics_statsd_model_json['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model_json['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model_json['Prefix'] = 'server'

        # Construct a model instance of ConfigOrdererMetricsStatsd by calling from_dict on the json representation
        config_orderer_metrics_statsd_model = ConfigOrdererMetricsStatsd.from_dict(config_orderer_metrics_statsd_model_json)
        assert config_orderer_metrics_statsd_model != False

        # Construct a model instance of ConfigOrdererMetricsStatsd by calling from_dict on the json representation
        config_orderer_metrics_statsd_model_dict = ConfigOrdererMetricsStatsd.from_dict(config_orderer_metrics_statsd_model_json).__dict__
        config_orderer_metrics_statsd_model2 = ConfigOrdererMetricsStatsd(**config_orderer_metrics_statsd_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_metrics_statsd_model == config_orderer_metrics_statsd_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_metrics_statsd_model_json2 = config_orderer_metrics_statsd_model.to_dict()
        assert config_orderer_metrics_statsd_model_json2 == config_orderer_metrics_statsd_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererUpdate
#-----------------------------------------------------------------------------
class TestConfigOrdererUpdate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererUpdate
    #--------------------------------------------------------
    def test_config_orderer_update_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_orderer_authentication_model = {} # ConfigOrdererAuthentication
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        config_orderer_keepalive_model = {} # ConfigOrdererKeepalive
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        config_orderer_metrics_statsd_model = {} # ConfigOrdererMetricsStatsd
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        config_orderer_debug_model = {} # ConfigOrdererDebug
        config_orderer_debug_model['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model['DeliverTraceDir'] = 'testString'

        config_orderer_general_update_model = {} # ConfigOrdererGeneralUpdate
        config_orderer_general_update_model['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_update_model['Authentication'] = config_orderer_authentication_model

        config_orderer_metrics_model = {} # ConfigOrdererMetrics
        config_orderer_metrics_model['Provider'] = 'disabled'
        config_orderer_metrics_model['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a json representation of a ConfigOrdererUpdate model
        config_orderer_update_model_json = {}
        config_orderer_update_model_json['General'] = config_orderer_general_update_model
        config_orderer_update_model_json['Debug'] = config_orderer_debug_model
        config_orderer_update_model_json['Metrics'] = config_orderer_metrics_model

        # Construct a model instance of ConfigOrdererUpdate by calling from_dict on the json representation
        config_orderer_update_model = ConfigOrdererUpdate.from_dict(config_orderer_update_model_json)
        assert config_orderer_update_model != False

        # Construct a model instance of ConfigOrdererUpdate by calling from_dict on the json representation
        config_orderer_update_model_dict = ConfigOrdererUpdate.from_dict(config_orderer_update_model_json).__dict__
        config_orderer_update_model2 = ConfigOrdererUpdate(**config_orderer_update_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_update_model == config_orderer_update_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_update_model_json2 = config_orderer_update_model.to_dict()
        assert config_orderer_update_model_json2 == config_orderer_update_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererAuthentication
#-----------------------------------------------------------------------------
class TestConfigOrdererAuthentication():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererAuthentication
    #--------------------------------------------------------
    def test_config_orderer_authentication_serialization(self):

        # Construct a json representation of a ConfigOrdererAuthentication model
        config_orderer_authentication_model_json = {}
        config_orderer_authentication_model_json['TimeWindow'] = '15m'
        config_orderer_authentication_model_json['NoExpirationChecks'] = False

        # Construct a model instance of ConfigOrdererAuthentication by calling from_dict on the json representation
        config_orderer_authentication_model = ConfigOrdererAuthentication.from_dict(config_orderer_authentication_model_json)
        assert config_orderer_authentication_model != False

        # Construct a model instance of ConfigOrdererAuthentication by calling from_dict on the json representation
        config_orderer_authentication_model_dict = ConfigOrdererAuthentication.from_dict(config_orderer_authentication_model_json).__dict__
        config_orderer_authentication_model2 = ConfigOrdererAuthentication(**config_orderer_authentication_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_authentication_model == config_orderer_authentication_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_authentication_model_json2 = config_orderer_authentication_model.to_dict()
        assert config_orderer_authentication_model_json2 == config_orderer_authentication_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererDebug
#-----------------------------------------------------------------------------
class TestConfigOrdererDebug():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererDebug
    #--------------------------------------------------------
    def test_config_orderer_debug_serialization(self):

        # Construct a json representation of a ConfigOrdererDebug model
        config_orderer_debug_model_json = {}
        config_orderer_debug_model_json['BroadcastTraceDir'] = 'testString'
        config_orderer_debug_model_json['DeliverTraceDir'] = 'testString'

        # Construct a model instance of ConfigOrdererDebug by calling from_dict on the json representation
        config_orderer_debug_model = ConfigOrdererDebug.from_dict(config_orderer_debug_model_json)
        assert config_orderer_debug_model != False

        # Construct a model instance of ConfigOrdererDebug by calling from_dict on the json representation
        config_orderer_debug_model_dict = ConfigOrdererDebug.from_dict(config_orderer_debug_model_json).__dict__
        config_orderer_debug_model2 = ConfigOrdererDebug(**config_orderer_debug_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_debug_model == config_orderer_debug_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_debug_model_json2 = config_orderer_debug_model.to_dict()
        assert config_orderer_debug_model_json2 == config_orderer_debug_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererGeneral
#-----------------------------------------------------------------------------
class TestConfigOrdererGeneral():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererGeneral
    #--------------------------------------------------------
    def test_config_orderer_general_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_orderer_authentication_model = {} # ConfigOrdererAuthentication
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        config_orderer_keepalive_model = {} # ConfigOrdererKeepalive
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        # Construct a json representation of a ConfigOrdererGeneral model
        config_orderer_general_model_json = {}
        config_orderer_general_model_json['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_model_json['BCCSP'] = bccsp_model
        config_orderer_general_model_json['Authentication'] = config_orderer_authentication_model

        # Construct a model instance of ConfigOrdererGeneral by calling from_dict on the json representation
        config_orderer_general_model = ConfigOrdererGeneral.from_dict(config_orderer_general_model_json)
        assert config_orderer_general_model != False

        # Construct a model instance of ConfigOrdererGeneral by calling from_dict on the json representation
        config_orderer_general_model_dict = ConfigOrdererGeneral.from_dict(config_orderer_general_model_json).__dict__
        config_orderer_general_model2 = ConfigOrdererGeneral(**config_orderer_general_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_general_model == config_orderer_general_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_general_model_json2 = config_orderer_general_model.to_dict()
        assert config_orderer_general_model_json2 == config_orderer_general_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererGeneralUpdate
#-----------------------------------------------------------------------------
class TestConfigOrdererGeneralUpdate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererGeneralUpdate
    #--------------------------------------------------------
    def test_config_orderer_general_update_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_orderer_authentication_model = {} # ConfigOrdererAuthentication
        config_orderer_authentication_model['TimeWindow'] = '15m'
        config_orderer_authentication_model['NoExpirationChecks'] = False

        config_orderer_keepalive_model = {} # ConfigOrdererKeepalive
        config_orderer_keepalive_model['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model['ServerInterval'] = '2h'
        config_orderer_keepalive_model['ServerTimeout'] = '20s'

        # Construct a json representation of a ConfigOrdererGeneralUpdate model
        config_orderer_general_update_model_json = {}
        config_orderer_general_update_model_json['Keepalive'] = config_orderer_keepalive_model
        config_orderer_general_update_model_json['Authentication'] = config_orderer_authentication_model

        # Construct a model instance of ConfigOrdererGeneralUpdate by calling from_dict on the json representation
        config_orderer_general_update_model = ConfigOrdererGeneralUpdate.from_dict(config_orderer_general_update_model_json)
        assert config_orderer_general_update_model != False

        # Construct a model instance of ConfigOrdererGeneralUpdate by calling from_dict on the json representation
        config_orderer_general_update_model_dict = ConfigOrdererGeneralUpdate.from_dict(config_orderer_general_update_model_json).__dict__
        config_orderer_general_update_model2 = ConfigOrdererGeneralUpdate(**config_orderer_general_update_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_general_update_model == config_orderer_general_update_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_general_update_model_json2 = config_orderer_general_update_model.to_dict()
        assert config_orderer_general_update_model_json2 == config_orderer_general_update_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererKeepalive
#-----------------------------------------------------------------------------
class TestConfigOrdererKeepalive():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererKeepalive
    #--------------------------------------------------------
    def test_config_orderer_keepalive_serialization(self):

        # Construct a json representation of a ConfigOrdererKeepalive model
        config_orderer_keepalive_model_json = {}
        config_orderer_keepalive_model_json['ServerMinInterval'] = '60s'
        config_orderer_keepalive_model_json['ServerInterval'] = '2h'
        config_orderer_keepalive_model_json['ServerTimeout'] = '20s'

        # Construct a model instance of ConfigOrdererKeepalive by calling from_dict on the json representation
        config_orderer_keepalive_model = ConfigOrdererKeepalive.from_dict(config_orderer_keepalive_model_json)
        assert config_orderer_keepalive_model != False

        # Construct a model instance of ConfigOrdererKeepalive by calling from_dict on the json representation
        config_orderer_keepalive_model_dict = ConfigOrdererKeepalive.from_dict(config_orderer_keepalive_model_json).__dict__
        config_orderer_keepalive_model2 = ConfigOrdererKeepalive(**config_orderer_keepalive_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_keepalive_model == config_orderer_keepalive_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_keepalive_model_json2 = config_orderer_keepalive_model.to_dict()
        assert config_orderer_keepalive_model_json2 == config_orderer_keepalive_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigOrdererMetrics
#-----------------------------------------------------------------------------
class TestConfigOrdererMetrics():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigOrdererMetrics
    #--------------------------------------------------------
    def test_config_orderer_metrics_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_orderer_metrics_statsd_model = {} # ConfigOrdererMetricsStatsd
        config_orderer_metrics_statsd_model['Network'] = 'udp'
        config_orderer_metrics_statsd_model['Address'] = '127.0.0.1:8125'
        config_orderer_metrics_statsd_model['WriteInterval'] = '10s'
        config_orderer_metrics_statsd_model['Prefix'] = 'server'

        # Construct a json representation of a ConfigOrdererMetrics model
        config_orderer_metrics_model_json = {}
        config_orderer_metrics_model_json['Provider'] = 'disabled'
        config_orderer_metrics_model_json['Statsd'] = config_orderer_metrics_statsd_model

        # Construct a model instance of ConfigOrdererMetrics by calling from_dict on the json representation
        config_orderer_metrics_model = ConfigOrdererMetrics.from_dict(config_orderer_metrics_model_json)
        assert config_orderer_metrics_model != False

        # Construct a model instance of ConfigOrdererMetrics by calling from_dict on the json representation
        config_orderer_metrics_model_dict = ConfigOrdererMetrics.from_dict(config_orderer_metrics_model_json).__dict__
        config_orderer_metrics_model2 = ConfigOrdererMetrics(**config_orderer_metrics_model_dict)

        # Verify the model instances are equivalent
        assert config_orderer_metrics_model == config_orderer_metrics_model2

        # Convert model instance back to dict and verify no loss of data
        config_orderer_metrics_model_json2 = config_orderer_metrics_model.to_dict()
        assert config_orderer_metrics_model_json2 == config_orderer_metrics_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerChaincodeExternalBuildersItem
#-----------------------------------------------------------------------------
class TestConfigPeerChaincodeExternalBuildersItem():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerChaincodeExternalBuildersItem
    #--------------------------------------------------------
    def test_config_peer_chaincode_external_builders_item_serialization(self):

        # Construct a json representation of a ConfigPeerChaincodeExternalBuildersItem model
        config_peer_chaincode_external_builders_item_model_json = {}
        config_peer_chaincode_external_builders_item_model_json['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model_json['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model_json['environmentWhitelist'] = ['GOPROXY']

        # Construct a model instance of ConfigPeerChaincodeExternalBuildersItem by calling from_dict on the json representation
        config_peer_chaincode_external_builders_item_model = ConfigPeerChaincodeExternalBuildersItem.from_dict(config_peer_chaincode_external_builders_item_model_json)
        assert config_peer_chaincode_external_builders_item_model != False

        # Construct a model instance of ConfigPeerChaincodeExternalBuildersItem by calling from_dict on the json representation
        config_peer_chaincode_external_builders_item_model_dict = ConfigPeerChaincodeExternalBuildersItem.from_dict(config_peer_chaincode_external_builders_item_model_json).__dict__
        config_peer_chaincode_external_builders_item_model2 = ConfigPeerChaincodeExternalBuildersItem(**config_peer_chaincode_external_builders_item_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_chaincode_external_builders_item_model == config_peer_chaincode_external_builders_item_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_chaincode_external_builders_item_model_json2 = config_peer_chaincode_external_builders_item_model.to_dict()
        assert config_peer_chaincode_external_builders_item_model_json2 == config_peer_chaincode_external_builders_item_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerChaincodeGolang
#-----------------------------------------------------------------------------
class TestConfigPeerChaincodeGolang():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerChaincodeGolang
    #--------------------------------------------------------
    def test_config_peer_chaincode_golang_serialization(self):

        # Construct a json representation of a ConfigPeerChaincodeGolang model
        config_peer_chaincode_golang_model_json = {}
        config_peer_chaincode_golang_model_json['dynamicLink'] = False

        # Construct a model instance of ConfigPeerChaincodeGolang by calling from_dict on the json representation
        config_peer_chaincode_golang_model = ConfigPeerChaincodeGolang.from_dict(config_peer_chaincode_golang_model_json)
        assert config_peer_chaincode_golang_model != False

        # Construct a model instance of ConfigPeerChaincodeGolang by calling from_dict on the json representation
        config_peer_chaincode_golang_model_dict = ConfigPeerChaincodeGolang.from_dict(config_peer_chaincode_golang_model_json).__dict__
        config_peer_chaincode_golang_model2 = ConfigPeerChaincodeGolang(**config_peer_chaincode_golang_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_chaincode_golang_model == config_peer_chaincode_golang_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_chaincode_golang_model_json2 = config_peer_chaincode_golang_model.to_dict()
        assert config_peer_chaincode_golang_model_json2 == config_peer_chaincode_golang_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerChaincodeLogging
#-----------------------------------------------------------------------------
class TestConfigPeerChaincodeLogging():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerChaincodeLogging
    #--------------------------------------------------------
    def test_config_peer_chaincode_logging_serialization(self):

        # Construct a json representation of a ConfigPeerChaincodeLogging model
        config_peer_chaincode_logging_model_json = {}
        config_peer_chaincode_logging_model_json['level'] = 'info'
        config_peer_chaincode_logging_model_json['shim'] = 'warning'
        config_peer_chaincode_logging_model_json['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        # Construct a model instance of ConfigPeerChaincodeLogging by calling from_dict on the json representation
        config_peer_chaincode_logging_model = ConfigPeerChaincodeLogging.from_dict(config_peer_chaincode_logging_model_json)
        assert config_peer_chaincode_logging_model != False

        # Construct a model instance of ConfigPeerChaincodeLogging by calling from_dict on the json representation
        config_peer_chaincode_logging_model_dict = ConfigPeerChaincodeLogging.from_dict(config_peer_chaincode_logging_model_json).__dict__
        config_peer_chaincode_logging_model2 = ConfigPeerChaincodeLogging(**config_peer_chaincode_logging_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_chaincode_logging_model == config_peer_chaincode_logging_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_chaincode_logging_model_json2 = config_peer_chaincode_logging_model.to_dict()
        assert config_peer_chaincode_logging_model_json2 == config_peer_chaincode_logging_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerChaincodeSystem
#-----------------------------------------------------------------------------
class TestConfigPeerChaincodeSystem():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerChaincodeSystem
    #--------------------------------------------------------
    def test_config_peer_chaincode_system_serialization(self):

        # Construct a json representation of a ConfigPeerChaincodeSystem model
        config_peer_chaincode_system_model_json = {}
        config_peer_chaincode_system_model_json['cscc'] = True
        config_peer_chaincode_system_model_json['lscc'] = True
        config_peer_chaincode_system_model_json['escc'] = True
        config_peer_chaincode_system_model_json['vscc'] = True
        config_peer_chaincode_system_model_json['qscc'] = True

        # Construct a model instance of ConfigPeerChaincodeSystem by calling from_dict on the json representation
        config_peer_chaincode_system_model = ConfigPeerChaincodeSystem.from_dict(config_peer_chaincode_system_model_json)
        assert config_peer_chaincode_system_model != False

        # Construct a model instance of ConfigPeerChaincodeSystem by calling from_dict on the json representation
        config_peer_chaincode_system_model_dict = ConfigPeerChaincodeSystem.from_dict(config_peer_chaincode_system_model_json).__dict__
        config_peer_chaincode_system_model2 = ConfigPeerChaincodeSystem(**config_peer_chaincode_system_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_chaincode_system_model == config_peer_chaincode_system_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_chaincode_system_model_json2 = config_peer_chaincode_system_model.to_dict()
        assert config_peer_chaincode_system_model_json2 == config_peer_chaincode_system_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerCreate
#-----------------------------------------------------------------------------
class TestConfigPeerCreate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerCreate
    #--------------------------------------------------------
    def test_config_peer_create_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {} # ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        config_peer_deliveryclient_address_overrides_item_model = {} # ConfigPeerDeliveryclientAddressOverridesItem
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        config_peer_gossip_election_model = {} # ConfigPeerGossipElection
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        config_peer_gossip_pvt_data_model = {} # ConfigPeerGossipPvtData
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        config_peer_gossip_state_model = {} # ConfigPeerGossipState
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        config_peer_keepalive_client_model = {} # ConfigPeerKeepaliveClient
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        config_peer_keepalive_delivery_client_model = {} # ConfigPeerKeepaliveDeliveryClient
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        config_peer_limits_concurrency_model = {} # ConfigPeerLimitsConcurrency
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_peer_admin_service_model = {} # ConfigPeerAdminService
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        config_peer_authentication_model = {} # ConfigPeerAuthentication
        config_peer_authentication_model['timewindow'] = '15m'

        config_peer_chaincode_external_builders_item_model = {} # ConfigPeerChaincodeExternalBuildersItem
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        config_peer_chaincode_golang_model = {} # ConfigPeerChaincodeGolang
        config_peer_chaincode_golang_model['dynamicLink'] = False

        config_peer_chaincode_logging_model = {} # ConfigPeerChaincodeLogging
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        config_peer_chaincode_system_model = {} # ConfigPeerChaincodeSystem
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        config_peer_client_model = {} # ConfigPeerClient
        config_peer_client_model['connTimeout'] = '2s'

        config_peer_deliveryclient_model = {} # ConfigPeerDeliveryclient
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        config_peer_discovery_model = {} # ConfigPeerDiscovery
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        config_peer_gossip_model = {} # ConfigPeerGossip
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        config_peer_keepalive_model = {} # ConfigPeerKeepalive
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        config_peer_limits_model = {} # ConfigPeerLimits
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        config_peer_chaincode_model = {} # ConfigPeerChaincode
        config_peer_chaincode_model['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model['installTimeout'] = '300s'
        config_peer_chaincode_model['startuptimeout'] = '300s'
        config_peer_chaincode_model['executetimeout'] = '30s'
        config_peer_chaincode_model['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model['logging'] = config_peer_chaincode_logging_model

        config_peer_create_peer_model = {} # ConfigPeerCreatePeer
        config_peer_create_peer_model['id'] = 'john-doe'
        config_peer_create_peer_model['networkId'] = 'dev'
        config_peer_create_peer_model['keepalive'] = config_peer_keepalive_model
        config_peer_create_peer_model['gossip'] = config_peer_gossip_model
        config_peer_create_peer_model['authentication'] = config_peer_authentication_model
        config_peer_create_peer_model['BCCSP'] = bccsp_model
        config_peer_create_peer_model['client'] = config_peer_client_model
        config_peer_create_peer_model['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_create_peer_model['adminService'] = config_peer_admin_service_model
        config_peer_create_peer_model['validatorPoolSize'] = 8
        config_peer_create_peer_model['discovery'] = config_peer_discovery_model
        config_peer_create_peer_model['limits'] = config_peer_limits_model

        metrics_model = {} # Metrics
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a json representation of a ConfigPeerCreate model
        config_peer_create_model_json = {}
        config_peer_create_model_json['peer'] = config_peer_create_peer_model
        config_peer_create_model_json['chaincode'] = config_peer_chaincode_model
        config_peer_create_model_json['metrics'] = metrics_model

        # Construct a model instance of ConfigPeerCreate by calling from_dict on the json representation
        config_peer_create_model = ConfigPeerCreate.from_dict(config_peer_create_model_json)
        assert config_peer_create_model != False

        # Construct a model instance of ConfigPeerCreate by calling from_dict on the json representation
        config_peer_create_model_dict = ConfigPeerCreate.from_dict(config_peer_create_model_json).__dict__
        config_peer_create_model2 = ConfigPeerCreate(**config_peer_create_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_create_model == config_peer_create_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_create_model_json2 = config_peer_create_model.to_dict()
        assert config_peer_create_model_json2 == config_peer_create_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerCreatePeer
#-----------------------------------------------------------------------------
class TestConfigPeerCreatePeer():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerCreatePeer
    #--------------------------------------------------------
    def test_config_peer_create_peer_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {} # ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        config_peer_deliveryclient_address_overrides_item_model = {} # ConfigPeerDeliveryclientAddressOverridesItem
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        config_peer_gossip_election_model = {} # ConfigPeerGossipElection
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        config_peer_gossip_pvt_data_model = {} # ConfigPeerGossipPvtData
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        config_peer_gossip_state_model = {} # ConfigPeerGossipState
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        config_peer_keepalive_client_model = {} # ConfigPeerKeepaliveClient
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        config_peer_keepalive_delivery_client_model = {} # ConfigPeerKeepaliveDeliveryClient
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        config_peer_limits_concurrency_model = {} # ConfigPeerLimitsConcurrency
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_peer_admin_service_model = {} # ConfigPeerAdminService
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        config_peer_authentication_model = {} # ConfigPeerAuthentication
        config_peer_authentication_model['timewindow'] = '15m'

        config_peer_client_model = {} # ConfigPeerClient
        config_peer_client_model['connTimeout'] = '2s'

        config_peer_deliveryclient_model = {} # ConfigPeerDeliveryclient
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        config_peer_discovery_model = {} # ConfigPeerDiscovery
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        config_peer_gossip_model = {} # ConfigPeerGossip
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        config_peer_keepalive_model = {} # ConfigPeerKeepalive
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        config_peer_limits_model = {} # ConfigPeerLimits
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        # Construct a json representation of a ConfigPeerCreatePeer model
        config_peer_create_peer_model_json = {}
        config_peer_create_peer_model_json['id'] = 'john-doe'
        config_peer_create_peer_model_json['networkId'] = 'dev'
        config_peer_create_peer_model_json['keepalive'] = config_peer_keepalive_model
        config_peer_create_peer_model_json['gossip'] = config_peer_gossip_model
        config_peer_create_peer_model_json['authentication'] = config_peer_authentication_model
        config_peer_create_peer_model_json['BCCSP'] = bccsp_model
        config_peer_create_peer_model_json['client'] = config_peer_client_model
        config_peer_create_peer_model_json['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_create_peer_model_json['adminService'] = config_peer_admin_service_model
        config_peer_create_peer_model_json['validatorPoolSize'] = 8
        config_peer_create_peer_model_json['discovery'] = config_peer_discovery_model
        config_peer_create_peer_model_json['limits'] = config_peer_limits_model

        # Construct a model instance of ConfigPeerCreatePeer by calling from_dict on the json representation
        config_peer_create_peer_model = ConfigPeerCreatePeer.from_dict(config_peer_create_peer_model_json)
        assert config_peer_create_peer_model != False

        # Construct a model instance of ConfigPeerCreatePeer by calling from_dict on the json representation
        config_peer_create_peer_model_dict = ConfigPeerCreatePeer.from_dict(config_peer_create_peer_model_json).__dict__
        config_peer_create_peer_model2 = ConfigPeerCreatePeer(**config_peer_create_peer_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_create_peer_model == config_peer_create_peer_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_create_peer_model_json2 = config_peer_create_peer_model.to_dict()
        assert config_peer_create_peer_model_json2 == config_peer_create_peer_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerDeliveryclientAddressOverridesItem
#-----------------------------------------------------------------------------
class TestConfigPeerDeliveryclientAddressOverridesItem():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerDeliveryclientAddressOverridesItem
    #--------------------------------------------------------
    def test_config_peer_deliveryclient_address_overrides_item_serialization(self):

        # Construct a json representation of a ConfigPeerDeliveryclientAddressOverridesItem model
        config_peer_deliveryclient_address_overrides_item_model_json = {}
        config_peer_deliveryclient_address_overrides_item_model_json['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model_json['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model_json['caCertsFile'] = 'my-data/cert.pem'

        # Construct a model instance of ConfigPeerDeliveryclientAddressOverridesItem by calling from_dict on the json representation
        config_peer_deliveryclient_address_overrides_item_model = ConfigPeerDeliveryclientAddressOverridesItem.from_dict(config_peer_deliveryclient_address_overrides_item_model_json)
        assert config_peer_deliveryclient_address_overrides_item_model != False

        # Construct a model instance of ConfigPeerDeliveryclientAddressOverridesItem by calling from_dict on the json representation
        config_peer_deliveryclient_address_overrides_item_model_dict = ConfigPeerDeliveryclientAddressOverridesItem.from_dict(config_peer_deliveryclient_address_overrides_item_model_json).__dict__
        config_peer_deliveryclient_address_overrides_item_model2 = ConfigPeerDeliveryclientAddressOverridesItem(**config_peer_deliveryclient_address_overrides_item_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_deliveryclient_address_overrides_item_model == config_peer_deliveryclient_address_overrides_item_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_deliveryclient_address_overrides_item_model_json2 = config_peer_deliveryclient_address_overrides_item_model.to_dict()
        assert config_peer_deliveryclient_address_overrides_item_model_json2 == config_peer_deliveryclient_address_overrides_item_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerGossipElection
#-----------------------------------------------------------------------------
class TestConfigPeerGossipElection():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerGossipElection
    #--------------------------------------------------------
    def test_config_peer_gossip_election_serialization(self):

        # Construct a json representation of a ConfigPeerGossipElection model
        config_peer_gossip_election_model_json = {}
        config_peer_gossip_election_model_json['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model_json['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model_json['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model_json['leaderElectionDuration'] = '5s'

        # Construct a model instance of ConfigPeerGossipElection by calling from_dict on the json representation
        config_peer_gossip_election_model = ConfigPeerGossipElection.from_dict(config_peer_gossip_election_model_json)
        assert config_peer_gossip_election_model != False

        # Construct a model instance of ConfigPeerGossipElection by calling from_dict on the json representation
        config_peer_gossip_election_model_dict = ConfigPeerGossipElection.from_dict(config_peer_gossip_election_model_json).__dict__
        config_peer_gossip_election_model2 = ConfigPeerGossipElection(**config_peer_gossip_election_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_gossip_election_model == config_peer_gossip_election_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_gossip_election_model_json2 = config_peer_gossip_election_model.to_dict()
        assert config_peer_gossip_election_model_json2 == config_peer_gossip_election_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerGossipPvtData
#-----------------------------------------------------------------------------
class TestConfigPeerGossipPvtData():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerGossipPvtData
    #--------------------------------------------------------
    def test_config_peer_gossip_pvt_data_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {} # ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        # Construct a json representation of a ConfigPeerGossipPvtData model
        config_peer_gossip_pvt_data_model_json = {}
        config_peer_gossip_pvt_data_model_json['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model_json['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model_json['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model_json['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model_json['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model_json['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model_json['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model_json['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model_json['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        # Construct a model instance of ConfigPeerGossipPvtData by calling from_dict on the json representation
        config_peer_gossip_pvt_data_model = ConfigPeerGossipPvtData.from_dict(config_peer_gossip_pvt_data_model_json)
        assert config_peer_gossip_pvt_data_model != False

        # Construct a model instance of ConfigPeerGossipPvtData by calling from_dict on the json representation
        config_peer_gossip_pvt_data_model_dict = ConfigPeerGossipPvtData.from_dict(config_peer_gossip_pvt_data_model_json).__dict__
        config_peer_gossip_pvt_data_model2 = ConfigPeerGossipPvtData(**config_peer_gossip_pvt_data_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_gossip_pvt_data_model == config_peer_gossip_pvt_data_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_gossip_pvt_data_model_json2 = config_peer_gossip_pvt_data_model.to_dict()
        assert config_peer_gossip_pvt_data_model_json2 == config_peer_gossip_pvt_data_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
#-----------------------------------------------------------------------------
class TestConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
    #--------------------------------------------------------
    def test_config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_serialization(self):

        # Construct a json representation of a ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy model
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json = {}
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json['maxPeerCount'] = 1

        # Construct a model instance of ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy by calling from_dict on the json representation
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy.from_dict(config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json)
        assert config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model != False

        # Construct a model instance of ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy by calling from_dict on the json representation
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_dict = ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy.from_dict(config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json).__dict__
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model2 = ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy(**config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model == config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json2 = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model.to_dict()
        assert config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json2 == config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerGossipState
#-----------------------------------------------------------------------------
class TestConfigPeerGossipState():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerGossipState
    #--------------------------------------------------------
    def test_config_peer_gossip_state_serialization(self):

        # Construct a json representation of a ConfigPeerGossipState model
        config_peer_gossip_state_model_json = {}
        config_peer_gossip_state_model_json['enabled'] = True
        config_peer_gossip_state_model_json['checkInterval'] = '10s'
        config_peer_gossip_state_model_json['responseTimeout'] = '3s'
        config_peer_gossip_state_model_json['batchSize'] = 10
        config_peer_gossip_state_model_json['blockBufferSize'] = 100
        config_peer_gossip_state_model_json['maxRetries'] = 3

        # Construct a model instance of ConfigPeerGossipState by calling from_dict on the json representation
        config_peer_gossip_state_model = ConfigPeerGossipState.from_dict(config_peer_gossip_state_model_json)
        assert config_peer_gossip_state_model != False

        # Construct a model instance of ConfigPeerGossipState by calling from_dict on the json representation
        config_peer_gossip_state_model_dict = ConfigPeerGossipState.from_dict(config_peer_gossip_state_model_json).__dict__
        config_peer_gossip_state_model2 = ConfigPeerGossipState(**config_peer_gossip_state_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_gossip_state_model == config_peer_gossip_state_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_gossip_state_model_json2 = config_peer_gossip_state_model.to_dict()
        assert config_peer_gossip_state_model_json2 == config_peer_gossip_state_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerKeepaliveClient
#-----------------------------------------------------------------------------
class TestConfigPeerKeepaliveClient():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerKeepaliveClient
    #--------------------------------------------------------
    def test_config_peer_keepalive_client_serialization(self):

        # Construct a json representation of a ConfigPeerKeepaliveClient model
        config_peer_keepalive_client_model_json = {}
        config_peer_keepalive_client_model_json['interval'] = '60s'
        config_peer_keepalive_client_model_json['timeout'] = '20s'

        # Construct a model instance of ConfigPeerKeepaliveClient by calling from_dict on the json representation
        config_peer_keepalive_client_model = ConfigPeerKeepaliveClient.from_dict(config_peer_keepalive_client_model_json)
        assert config_peer_keepalive_client_model != False

        # Construct a model instance of ConfigPeerKeepaliveClient by calling from_dict on the json representation
        config_peer_keepalive_client_model_dict = ConfigPeerKeepaliveClient.from_dict(config_peer_keepalive_client_model_json).__dict__
        config_peer_keepalive_client_model2 = ConfigPeerKeepaliveClient(**config_peer_keepalive_client_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_keepalive_client_model == config_peer_keepalive_client_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_keepalive_client_model_json2 = config_peer_keepalive_client_model.to_dict()
        assert config_peer_keepalive_client_model_json2 == config_peer_keepalive_client_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerKeepaliveDeliveryClient
#-----------------------------------------------------------------------------
class TestConfigPeerKeepaliveDeliveryClient():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerKeepaliveDeliveryClient
    #--------------------------------------------------------
    def test_config_peer_keepalive_delivery_client_serialization(self):

        # Construct a json representation of a ConfigPeerKeepaliveDeliveryClient model
        config_peer_keepalive_delivery_client_model_json = {}
        config_peer_keepalive_delivery_client_model_json['interval'] = '60s'
        config_peer_keepalive_delivery_client_model_json['timeout'] = '20s'

        # Construct a model instance of ConfigPeerKeepaliveDeliveryClient by calling from_dict on the json representation
        config_peer_keepalive_delivery_client_model = ConfigPeerKeepaliveDeliveryClient.from_dict(config_peer_keepalive_delivery_client_model_json)
        assert config_peer_keepalive_delivery_client_model != False

        # Construct a model instance of ConfigPeerKeepaliveDeliveryClient by calling from_dict on the json representation
        config_peer_keepalive_delivery_client_model_dict = ConfigPeerKeepaliveDeliveryClient.from_dict(config_peer_keepalive_delivery_client_model_json).__dict__
        config_peer_keepalive_delivery_client_model2 = ConfigPeerKeepaliveDeliveryClient(**config_peer_keepalive_delivery_client_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_keepalive_delivery_client_model == config_peer_keepalive_delivery_client_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_keepalive_delivery_client_model_json2 = config_peer_keepalive_delivery_client_model.to_dict()
        assert config_peer_keepalive_delivery_client_model_json2 == config_peer_keepalive_delivery_client_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerLimitsConcurrency
#-----------------------------------------------------------------------------
class TestConfigPeerLimitsConcurrency():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerLimitsConcurrency
    #--------------------------------------------------------
    def test_config_peer_limits_concurrency_serialization(self):

        # Construct a json representation of a ConfigPeerLimitsConcurrency model
        config_peer_limits_concurrency_model_json = {}
        config_peer_limits_concurrency_model_json['endorserService'] = 2500
        config_peer_limits_concurrency_model_json['deliverService'] = 2500

        # Construct a model instance of ConfigPeerLimitsConcurrency by calling from_dict on the json representation
        config_peer_limits_concurrency_model = ConfigPeerLimitsConcurrency.from_dict(config_peer_limits_concurrency_model_json)
        assert config_peer_limits_concurrency_model != False

        # Construct a model instance of ConfigPeerLimitsConcurrency by calling from_dict on the json representation
        config_peer_limits_concurrency_model_dict = ConfigPeerLimitsConcurrency.from_dict(config_peer_limits_concurrency_model_json).__dict__
        config_peer_limits_concurrency_model2 = ConfigPeerLimitsConcurrency(**config_peer_limits_concurrency_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_limits_concurrency_model == config_peer_limits_concurrency_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_limits_concurrency_model_json2 = config_peer_limits_concurrency_model.to_dict()
        assert config_peer_limits_concurrency_model_json2 == config_peer_limits_concurrency_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerUpdate
#-----------------------------------------------------------------------------
class TestConfigPeerUpdate():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerUpdate
    #--------------------------------------------------------
    def test_config_peer_update_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {} # ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        config_peer_deliveryclient_address_overrides_item_model = {} # ConfigPeerDeliveryclientAddressOverridesItem
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        config_peer_gossip_election_model = {} # ConfigPeerGossipElection
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        config_peer_gossip_pvt_data_model = {} # ConfigPeerGossipPvtData
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        config_peer_gossip_state_model = {} # ConfigPeerGossipState
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        config_peer_keepalive_client_model = {} # ConfigPeerKeepaliveClient
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        config_peer_keepalive_delivery_client_model = {} # ConfigPeerKeepaliveDeliveryClient
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        config_peer_limits_concurrency_model = {} # ConfigPeerLimitsConcurrency
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        config_peer_admin_service_model = {} # ConfigPeerAdminService
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        config_peer_authentication_model = {} # ConfigPeerAuthentication
        config_peer_authentication_model['timewindow'] = '15m'

        config_peer_chaincode_external_builders_item_model = {} # ConfigPeerChaincodeExternalBuildersItem
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        config_peer_chaincode_golang_model = {} # ConfigPeerChaincodeGolang
        config_peer_chaincode_golang_model['dynamicLink'] = False

        config_peer_chaincode_logging_model = {} # ConfigPeerChaincodeLogging
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        config_peer_chaincode_system_model = {} # ConfigPeerChaincodeSystem
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        config_peer_client_model = {} # ConfigPeerClient
        config_peer_client_model['connTimeout'] = '2s'

        config_peer_deliveryclient_model = {} # ConfigPeerDeliveryclient
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        config_peer_discovery_model = {} # ConfigPeerDiscovery
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        config_peer_gossip_model = {} # ConfigPeerGossip
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        config_peer_keepalive_model = {} # ConfigPeerKeepalive
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        config_peer_limits_model = {} # ConfigPeerLimits
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        config_peer_chaincode_model = {} # ConfigPeerChaincode
        config_peer_chaincode_model['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model['installTimeout'] = '300s'
        config_peer_chaincode_model['startuptimeout'] = '300s'
        config_peer_chaincode_model['executetimeout'] = '30s'
        config_peer_chaincode_model['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model['logging'] = config_peer_chaincode_logging_model

        config_peer_update_peer_model = {} # ConfigPeerUpdatePeer
        config_peer_update_peer_model['id'] = 'john-doe'
        config_peer_update_peer_model['networkId'] = 'dev'
        config_peer_update_peer_model['keepalive'] = config_peer_keepalive_model
        config_peer_update_peer_model['gossip'] = config_peer_gossip_model
        config_peer_update_peer_model['authentication'] = config_peer_authentication_model
        config_peer_update_peer_model['client'] = config_peer_client_model
        config_peer_update_peer_model['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_update_peer_model['adminService'] = config_peer_admin_service_model
        config_peer_update_peer_model['validatorPoolSize'] = 8
        config_peer_update_peer_model['discovery'] = config_peer_discovery_model
        config_peer_update_peer_model['limits'] = config_peer_limits_model

        metrics_model = {} # Metrics
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        # Construct a json representation of a ConfigPeerUpdate model
        config_peer_update_model_json = {}
        config_peer_update_model_json['peer'] = config_peer_update_peer_model
        config_peer_update_model_json['chaincode'] = config_peer_chaincode_model
        config_peer_update_model_json['metrics'] = metrics_model

        # Construct a model instance of ConfigPeerUpdate by calling from_dict on the json representation
        config_peer_update_model = ConfigPeerUpdate.from_dict(config_peer_update_model_json)
        assert config_peer_update_model != False

        # Construct a model instance of ConfigPeerUpdate by calling from_dict on the json representation
        config_peer_update_model_dict = ConfigPeerUpdate.from_dict(config_peer_update_model_json).__dict__
        config_peer_update_model2 = ConfigPeerUpdate(**config_peer_update_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_update_model == config_peer_update_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_update_model_json2 = config_peer_update_model.to_dict()
        assert config_peer_update_model_json2 == config_peer_update_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerUpdatePeer
#-----------------------------------------------------------------------------
class TestConfigPeerUpdatePeer():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerUpdatePeer
    #--------------------------------------------------------
    def test_config_peer_update_peer_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {} # ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        config_peer_deliveryclient_address_overrides_item_model = {} # ConfigPeerDeliveryclientAddressOverridesItem
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        config_peer_gossip_election_model = {} # ConfigPeerGossipElection
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        config_peer_gossip_pvt_data_model = {} # ConfigPeerGossipPvtData
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        config_peer_gossip_state_model = {} # ConfigPeerGossipState
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        config_peer_keepalive_client_model = {} # ConfigPeerKeepaliveClient
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        config_peer_keepalive_delivery_client_model = {} # ConfigPeerKeepaliveDeliveryClient
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        config_peer_limits_concurrency_model = {} # ConfigPeerLimitsConcurrency
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        config_peer_admin_service_model = {} # ConfigPeerAdminService
        config_peer_admin_service_model['listenAddress'] = '0.0.0.0:7051'

        config_peer_authentication_model = {} # ConfigPeerAuthentication
        config_peer_authentication_model['timewindow'] = '15m'

        config_peer_client_model = {} # ConfigPeerClient
        config_peer_client_model['connTimeout'] = '2s'

        config_peer_deliveryclient_model = {} # ConfigPeerDeliveryclient
        config_peer_deliveryclient_model['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model['connTimeout'] = '2s'
        config_peer_deliveryclient_model['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        config_peer_discovery_model = {} # ConfigPeerDiscovery
        config_peer_discovery_model['enabled'] = True
        config_peer_discovery_model['authCacheEnabled'] = True
        config_peer_discovery_model['authCacheMaxSize'] = 1000
        config_peer_discovery_model['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model['orgMembersAllowedAccess'] = False

        config_peer_gossip_model = {} # ConfigPeerGossip
        config_peer_gossip_model['useLeaderElection'] = True
        config_peer_gossip_model['orgLeader'] = False
        config_peer_gossip_model['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model['maxBlockCountToStore'] = 100
        config_peer_gossip_model['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model['maxPropagationBurstSize'] = 10
        config_peer_gossip_model['propagateIterations'] = 3
        config_peer_gossip_model['pullInterval'] = '4s'
        config_peer_gossip_model['pullPeerNum'] = 3
        config_peer_gossip_model['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model['publishCertPeriod'] = '10s'
        config_peer_gossip_model['skipBlockVerification'] = False
        config_peer_gossip_model['dialTimeout'] = '3s'
        config_peer_gossip_model['connTimeout'] = '2s'
        config_peer_gossip_model['recvBuffSize'] = 20
        config_peer_gossip_model['sendBuffSize'] = 200
        config_peer_gossip_model['digestWaitTime'] = '1s'
        config_peer_gossip_model['requestWaitTime'] = '1500ms'
        config_peer_gossip_model['responseWaitTime'] = '2s'
        config_peer_gossip_model['aliveTimeInterval'] = '5s'
        config_peer_gossip_model['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model['reconnectInterval'] = '25s'
        config_peer_gossip_model['election'] = config_peer_gossip_election_model
        config_peer_gossip_model['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model['state'] = config_peer_gossip_state_model

        config_peer_keepalive_model = {} # ConfigPeerKeepalive
        config_peer_keepalive_model['minInterval'] = '60s'
        config_peer_keepalive_model['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model['deliveryClient'] = config_peer_keepalive_delivery_client_model

        config_peer_limits_model = {} # ConfigPeerLimits
        config_peer_limits_model['concurrency'] = config_peer_limits_concurrency_model

        # Construct a json representation of a ConfigPeerUpdatePeer model
        config_peer_update_peer_model_json = {}
        config_peer_update_peer_model_json['id'] = 'john-doe'
        config_peer_update_peer_model_json['networkId'] = 'dev'
        config_peer_update_peer_model_json['keepalive'] = config_peer_keepalive_model
        config_peer_update_peer_model_json['gossip'] = config_peer_gossip_model
        config_peer_update_peer_model_json['authentication'] = config_peer_authentication_model
        config_peer_update_peer_model_json['client'] = config_peer_client_model
        config_peer_update_peer_model_json['deliveryclient'] = config_peer_deliveryclient_model
        config_peer_update_peer_model_json['adminService'] = config_peer_admin_service_model
        config_peer_update_peer_model_json['validatorPoolSize'] = 8
        config_peer_update_peer_model_json['discovery'] = config_peer_discovery_model
        config_peer_update_peer_model_json['limits'] = config_peer_limits_model

        # Construct a model instance of ConfigPeerUpdatePeer by calling from_dict on the json representation
        config_peer_update_peer_model = ConfigPeerUpdatePeer.from_dict(config_peer_update_peer_model_json)
        assert config_peer_update_peer_model != False

        # Construct a model instance of ConfigPeerUpdatePeer by calling from_dict on the json representation
        config_peer_update_peer_model_dict = ConfigPeerUpdatePeer.from_dict(config_peer_update_peer_model_json).__dict__
        config_peer_update_peer_model2 = ConfigPeerUpdatePeer(**config_peer_update_peer_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_update_peer_model == config_peer_update_peer_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_update_peer_model_json2 = config_peer_update_peer_model.to_dict()
        assert config_peer_update_peer_model_json2 == config_peer_update_peer_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerAdminService
#-----------------------------------------------------------------------------
class TestConfigPeerAdminService():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerAdminService
    #--------------------------------------------------------
    def test_config_peer_admin_service_serialization(self):

        # Construct a json representation of a ConfigPeerAdminService model
        config_peer_admin_service_model_json = {}
        config_peer_admin_service_model_json['listenAddress'] = '0.0.0.0:7051'

        # Construct a model instance of ConfigPeerAdminService by calling from_dict on the json representation
        config_peer_admin_service_model = ConfigPeerAdminService.from_dict(config_peer_admin_service_model_json)
        assert config_peer_admin_service_model != False

        # Construct a model instance of ConfigPeerAdminService by calling from_dict on the json representation
        config_peer_admin_service_model_dict = ConfigPeerAdminService.from_dict(config_peer_admin_service_model_json).__dict__
        config_peer_admin_service_model2 = ConfigPeerAdminService(**config_peer_admin_service_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_admin_service_model == config_peer_admin_service_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_admin_service_model_json2 = config_peer_admin_service_model.to_dict()
        assert config_peer_admin_service_model_json2 == config_peer_admin_service_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerAuthentication
#-----------------------------------------------------------------------------
class TestConfigPeerAuthentication():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerAuthentication
    #--------------------------------------------------------
    def test_config_peer_authentication_serialization(self):

        # Construct a json representation of a ConfigPeerAuthentication model
        config_peer_authentication_model_json = {}
        config_peer_authentication_model_json['timewindow'] = '15m'

        # Construct a model instance of ConfigPeerAuthentication by calling from_dict on the json representation
        config_peer_authentication_model = ConfigPeerAuthentication.from_dict(config_peer_authentication_model_json)
        assert config_peer_authentication_model != False

        # Construct a model instance of ConfigPeerAuthentication by calling from_dict on the json representation
        config_peer_authentication_model_dict = ConfigPeerAuthentication.from_dict(config_peer_authentication_model_json).__dict__
        config_peer_authentication_model2 = ConfigPeerAuthentication(**config_peer_authentication_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_authentication_model == config_peer_authentication_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_authentication_model_json2 = config_peer_authentication_model.to_dict()
        assert config_peer_authentication_model_json2 == config_peer_authentication_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerChaincode
#-----------------------------------------------------------------------------
class TestConfigPeerChaincode():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerChaincode
    #--------------------------------------------------------
    def test_config_peer_chaincode_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_chaincode_external_builders_item_model = {} # ConfigPeerChaincodeExternalBuildersItem
        config_peer_chaincode_external_builders_item_model['path'] = '/path/to/directory'
        config_peer_chaincode_external_builders_item_model['name'] = 'descriptive-build-name'
        config_peer_chaincode_external_builders_item_model['environmentWhitelist'] = ['GOPROXY']

        config_peer_chaincode_golang_model = {} # ConfigPeerChaincodeGolang
        config_peer_chaincode_golang_model['dynamicLink'] = False

        config_peer_chaincode_logging_model = {} # ConfigPeerChaincodeLogging
        config_peer_chaincode_logging_model['level'] = 'info'
        config_peer_chaincode_logging_model['shim'] = 'warning'
        config_peer_chaincode_logging_model['format'] = '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'

        config_peer_chaincode_system_model = {} # ConfigPeerChaincodeSystem
        config_peer_chaincode_system_model['cscc'] = True
        config_peer_chaincode_system_model['lscc'] = True
        config_peer_chaincode_system_model['escc'] = True
        config_peer_chaincode_system_model['vscc'] = True
        config_peer_chaincode_system_model['qscc'] = True

        # Construct a json representation of a ConfigPeerChaincode model
        config_peer_chaincode_model_json = {}
        config_peer_chaincode_model_json['golang'] = config_peer_chaincode_golang_model
        config_peer_chaincode_model_json['externalBuilders'] = [config_peer_chaincode_external_builders_item_model]
        config_peer_chaincode_model_json['installTimeout'] = '300s'
        config_peer_chaincode_model_json['startuptimeout'] = '300s'
        config_peer_chaincode_model_json['executetimeout'] = '30s'
        config_peer_chaincode_model_json['system'] = config_peer_chaincode_system_model
        config_peer_chaincode_model_json['logging'] = config_peer_chaincode_logging_model

        # Construct a model instance of ConfigPeerChaincode by calling from_dict on the json representation
        config_peer_chaincode_model = ConfigPeerChaincode.from_dict(config_peer_chaincode_model_json)
        assert config_peer_chaincode_model != False

        # Construct a model instance of ConfigPeerChaincode by calling from_dict on the json representation
        config_peer_chaincode_model_dict = ConfigPeerChaincode.from_dict(config_peer_chaincode_model_json).__dict__
        config_peer_chaincode_model2 = ConfigPeerChaincode(**config_peer_chaincode_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_chaincode_model == config_peer_chaincode_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_chaincode_model_json2 = config_peer_chaincode_model.to_dict()
        assert config_peer_chaincode_model_json2 == config_peer_chaincode_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerClient
#-----------------------------------------------------------------------------
class TestConfigPeerClient():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerClient
    #--------------------------------------------------------
    def test_config_peer_client_serialization(self):

        # Construct a json representation of a ConfigPeerClient model
        config_peer_client_model_json = {}
        config_peer_client_model_json['connTimeout'] = '2s'

        # Construct a model instance of ConfigPeerClient by calling from_dict on the json representation
        config_peer_client_model = ConfigPeerClient.from_dict(config_peer_client_model_json)
        assert config_peer_client_model != False

        # Construct a model instance of ConfigPeerClient by calling from_dict on the json representation
        config_peer_client_model_dict = ConfigPeerClient.from_dict(config_peer_client_model_json).__dict__
        config_peer_client_model2 = ConfigPeerClient(**config_peer_client_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_client_model == config_peer_client_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_client_model_json2 = config_peer_client_model.to_dict()
        assert config_peer_client_model_json2 == config_peer_client_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerDeliveryclient
#-----------------------------------------------------------------------------
class TestConfigPeerDeliveryclient():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerDeliveryclient
    #--------------------------------------------------------
    def test_config_peer_deliveryclient_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_deliveryclient_address_overrides_item_model = {} # ConfigPeerDeliveryclientAddressOverridesItem
        config_peer_deliveryclient_address_overrides_item_model['from'] = 'n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['to'] = 'n3a3ec3-myorderer2.ibp.us-south.containers.appdomain.cloud:7050'
        config_peer_deliveryclient_address_overrides_item_model['caCertsFile'] = 'my-data/cert.pem'

        # Construct a json representation of a ConfigPeerDeliveryclient model
        config_peer_deliveryclient_model_json = {}
        config_peer_deliveryclient_model_json['reconnectTotalTimeThreshold'] = '60m'
        config_peer_deliveryclient_model_json['connTimeout'] = '2s'
        config_peer_deliveryclient_model_json['reConnectBackoffThreshold'] = '60m'
        config_peer_deliveryclient_model_json['addressOverrides'] = [config_peer_deliveryclient_address_overrides_item_model]

        # Construct a model instance of ConfigPeerDeliveryclient by calling from_dict on the json representation
        config_peer_deliveryclient_model = ConfigPeerDeliveryclient.from_dict(config_peer_deliveryclient_model_json)
        assert config_peer_deliveryclient_model != False

        # Construct a model instance of ConfigPeerDeliveryclient by calling from_dict on the json representation
        config_peer_deliveryclient_model_dict = ConfigPeerDeliveryclient.from_dict(config_peer_deliveryclient_model_json).__dict__
        config_peer_deliveryclient_model2 = ConfigPeerDeliveryclient(**config_peer_deliveryclient_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_deliveryclient_model == config_peer_deliveryclient_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_deliveryclient_model_json2 = config_peer_deliveryclient_model.to_dict()
        assert config_peer_deliveryclient_model_json2 == config_peer_deliveryclient_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerDiscovery
#-----------------------------------------------------------------------------
class TestConfigPeerDiscovery():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerDiscovery
    #--------------------------------------------------------
    def test_config_peer_discovery_serialization(self):

        # Construct a json representation of a ConfigPeerDiscovery model
        config_peer_discovery_model_json = {}
        config_peer_discovery_model_json['enabled'] = True
        config_peer_discovery_model_json['authCacheEnabled'] = True
        config_peer_discovery_model_json['authCacheMaxSize'] = 1000
        config_peer_discovery_model_json['authCachePurgeRetentionRatio'] = 0.75
        config_peer_discovery_model_json['orgMembersAllowedAccess'] = False

        # Construct a model instance of ConfigPeerDiscovery by calling from_dict on the json representation
        config_peer_discovery_model = ConfigPeerDiscovery.from_dict(config_peer_discovery_model_json)
        assert config_peer_discovery_model != False

        # Construct a model instance of ConfigPeerDiscovery by calling from_dict on the json representation
        config_peer_discovery_model_dict = ConfigPeerDiscovery.from_dict(config_peer_discovery_model_json).__dict__
        config_peer_discovery_model2 = ConfigPeerDiscovery(**config_peer_discovery_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_discovery_model == config_peer_discovery_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_discovery_model_json2 = config_peer_discovery_model.to_dict()
        assert config_peer_discovery_model_json2 == config_peer_discovery_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerGossip
#-----------------------------------------------------------------------------
class TestConfigPeerGossip():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerGossip
    #--------------------------------------------------------
    def test_config_peer_gossip_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model = {} # ConfigPeerGossipPvtDataImplicitCollectionDisseminationPolicy
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['requiredPeerCount'] = 0
        config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model['maxPeerCount'] = 1

        config_peer_gossip_election_model = {} # ConfigPeerGossipElection
        config_peer_gossip_election_model['startupGracePeriod'] = '15s'
        config_peer_gossip_election_model['membershipSampleInterval'] = '1s'
        config_peer_gossip_election_model['leaderAliveThreshold'] = '10s'
        config_peer_gossip_election_model['leaderElectionDuration'] = '5s'

        config_peer_gossip_pvt_data_model = {} # ConfigPeerGossipPvtData
        config_peer_gossip_pvt_data_model['pullRetryThreshold'] = '60s'
        config_peer_gossip_pvt_data_model['transientstoreMaxBlockRetention'] = 1000
        config_peer_gossip_pvt_data_model['pushAckTimeout'] = '3s'
        config_peer_gossip_pvt_data_model['btlPullMargin'] = 10
        config_peer_gossip_pvt_data_model['reconcileBatchSize'] = 10
        config_peer_gossip_pvt_data_model['reconcileSleepInterval'] = '1m'
        config_peer_gossip_pvt_data_model['reconciliationEnabled'] = True
        config_peer_gossip_pvt_data_model['skipPullingInvalidTransactionsDuringCommit'] = False
        config_peer_gossip_pvt_data_model['implicitCollectionDisseminationPolicy'] = config_peer_gossip_pvt_data_implicit_collection_dissemination_policy_model

        config_peer_gossip_state_model = {} # ConfigPeerGossipState
        config_peer_gossip_state_model['enabled'] = True
        config_peer_gossip_state_model['checkInterval'] = '10s'
        config_peer_gossip_state_model['responseTimeout'] = '3s'
        config_peer_gossip_state_model['batchSize'] = 10
        config_peer_gossip_state_model['blockBufferSize'] = 100
        config_peer_gossip_state_model['maxRetries'] = 3

        # Construct a json representation of a ConfigPeerGossip model
        config_peer_gossip_model_json = {}
        config_peer_gossip_model_json['useLeaderElection'] = True
        config_peer_gossip_model_json['orgLeader'] = False
        config_peer_gossip_model_json['membershipTrackerInterval'] = '5s'
        config_peer_gossip_model_json['maxBlockCountToStore'] = 100
        config_peer_gossip_model_json['maxPropagationBurstLatency'] = '10ms'
        config_peer_gossip_model_json['maxPropagationBurstSize'] = 10
        config_peer_gossip_model_json['propagateIterations'] = 3
        config_peer_gossip_model_json['pullInterval'] = '4s'
        config_peer_gossip_model_json['pullPeerNum'] = 3
        config_peer_gossip_model_json['requestStateInfoInterval'] = '4s'
        config_peer_gossip_model_json['publishStateInfoInterval'] = '4s'
        config_peer_gossip_model_json['stateInfoRetentionInterval'] = '0s'
        config_peer_gossip_model_json['publishCertPeriod'] = '10s'
        config_peer_gossip_model_json['skipBlockVerification'] = False
        config_peer_gossip_model_json['dialTimeout'] = '3s'
        config_peer_gossip_model_json['connTimeout'] = '2s'
        config_peer_gossip_model_json['recvBuffSize'] = 20
        config_peer_gossip_model_json['sendBuffSize'] = 200
        config_peer_gossip_model_json['digestWaitTime'] = '1s'
        config_peer_gossip_model_json['requestWaitTime'] = '1500ms'
        config_peer_gossip_model_json['responseWaitTime'] = '2s'
        config_peer_gossip_model_json['aliveTimeInterval'] = '5s'
        config_peer_gossip_model_json['aliveExpirationTimeout'] = '25s'
        config_peer_gossip_model_json['reconnectInterval'] = '25s'
        config_peer_gossip_model_json['election'] = config_peer_gossip_election_model
        config_peer_gossip_model_json['pvtData'] = config_peer_gossip_pvt_data_model
        config_peer_gossip_model_json['state'] = config_peer_gossip_state_model

        # Construct a model instance of ConfigPeerGossip by calling from_dict on the json representation
        config_peer_gossip_model = ConfigPeerGossip.from_dict(config_peer_gossip_model_json)
        assert config_peer_gossip_model != False

        # Construct a model instance of ConfigPeerGossip by calling from_dict on the json representation
        config_peer_gossip_model_dict = ConfigPeerGossip.from_dict(config_peer_gossip_model_json).__dict__
        config_peer_gossip_model2 = ConfigPeerGossip(**config_peer_gossip_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_gossip_model == config_peer_gossip_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_gossip_model_json2 = config_peer_gossip_model.to_dict()
        assert config_peer_gossip_model_json2 == config_peer_gossip_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerKeepalive
#-----------------------------------------------------------------------------
class TestConfigPeerKeepalive():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerKeepalive
    #--------------------------------------------------------
    def test_config_peer_keepalive_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_keepalive_client_model = {} # ConfigPeerKeepaliveClient
        config_peer_keepalive_client_model['interval'] = '60s'
        config_peer_keepalive_client_model['timeout'] = '20s'

        config_peer_keepalive_delivery_client_model = {} # ConfigPeerKeepaliveDeliveryClient
        config_peer_keepalive_delivery_client_model['interval'] = '60s'
        config_peer_keepalive_delivery_client_model['timeout'] = '20s'

        # Construct a json representation of a ConfigPeerKeepalive model
        config_peer_keepalive_model_json = {}
        config_peer_keepalive_model_json['minInterval'] = '60s'
        config_peer_keepalive_model_json['client'] = config_peer_keepalive_client_model
        config_peer_keepalive_model_json['deliveryClient'] = config_peer_keepalive_delivery_client_model

        # Construct a model instance of ConfigPeerKeepalive by calling from_dict on the json representation
        config_peer_keepalive_model = ConfigPeerKeepalive.from_dict(config_peer_keepalive_model_json)
        assert config_peer_keepalive_model != False

        # Construct a model instance of ConfigPeerKeepalive by calling from_dict on the json representation
        config_peer_keepalive_model_dict = ConfigPeerKeepalive.from_dict(config_peer_keepalive_model_json).__dict__
        config_peer_keepalive_model2 = ConfigPeerKeepalive(**config_peer_keepalive_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_keepalive_model == config_peer_keepalive_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_keepalive_model_json2 = config_peer_keepalive_model.to_dict()
        assert config_peer_keepalive_model_json2 == config_peer_keepalive_model_json

#-----------------------------------------------------------------------------
# Test Class for ConfigPeerLimits
#-----------------------------------------------------------------------------
class TestConfigPeerLimits():

    #--------------------------------------------------------
    # Test serialization/deserialization for ConfigPeerLimits
    #--------------------------------------------------------
    def test_config_peer_limits_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_peer_limits_concurrency_model = {} # ConfigPeerLimitsConcurrency
        config_peer_limits_concurrency_model['endorserService'] = 2500
        config_peer_limits_concurrency_model['deliverService'] = 2500

        # Construct a json representation of a ConfigPeerLimits model
        config_peer_limits_model_json = {}
        config_peer_limits_model_json['concurrency'] = config_peer_limits_concurrency_model

        # Construct a model instance of ConfigPeerLimits by calling from_dict on the json representation
        config_peer_limits_model = ConfigPeerLimits.from_dict(config_peer_limits_model_json)
        assert config_peer_limits_model != False

        # Construct a model instance of ConfigPeerLimits by calling from_dict on the json representation
        config_peer_limits_model_dict = ConfigPeerLimits.from_dict(config_peer_limits_model_json).__dict__
        config_peer_limits_model2 = ConfigPeerLimits(**config_peer_limits_model_dict)

        # Verify the model instances are equivalent
        assert config_peer_limits_model == config_peer_limits_model2

        # Convert model instance back to dict and verify no loss of data
        config_peer_limits_model_json2 = config_peer_limits_model.to_dict()
        assert config_peer_limits_model_json2 == config_peer_limits_model_json

#-----------------------------------------------------------------------------
# Test Class for CpuHealthStats
#-----------------------------------------------------------------------------
class TestCpuHealthStats():

    #--------------------------------------------------------
    # Test serialization/deserialization for CpuHealthStats
    #--------------------------------------------------------
    def test_cpu_health_stats_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        cpu_health_stats_times_model = {} # CpuHealthStatsTimes
        cpu_health_stats_times_model['idle'] = 131397203
        cpu_health_stats_times_model['irq'] = 6068640
        cpu_health_stats_times_model['nice'] = 0
        cpu_health_stats_times_model['sys'] = 9652328
        cpu_health_stats_times_model['user'] = 4152187

        # Construct a json representation of a CpuHealthStats model
        cpu_health_stats_model_json = {}
        cpu_health_stats_model_json['model'] = 'Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz'
        cpu_health_stats_model_json['speed'] = 2592
        cpu_health_stats_model_json['times'] = cpu_health_stats_times_model

        # Construct a model instance of CpuHealthStats by calling from_dict on the json representation
        cpu_health_stats_model = CpuHealthStats.from_dict(cpu_health_stats_model_json)
        assert cpu_health_stats_model != False

        # Construct a model instance of CpuHealthStats by calling from_dict on the json representation
        cpu_health_stats_model_dict = CpuHealthStats.from_dict(cpu_health_stats_model_json).__dict__
        cpu_health_stats_model2 = CpuHealthStats(**cpu_health_stats_model_dict)

        # Verify the model instances are equivalent
        assert cpu_health_stats_model == cpu_health_stats_model2

        # Convert model instance back to dict and verify no loss of data
        cpu_health_stats_model_json2 = cpu_health_stats_model.to_dict()
        assert cpu_health_stats_model_json2 == cpu_health_stats_model_json

#-----------------------------------------------------------------------------
# Test Class for CpuHealthStatsTimes
#-----------------------------------------------------------------------------
class TestCpuHealthStatsTimes():

    #--------------------------------------------------------
    # Test serialization/deserialization for CpuHealthStatsTimes
    #--------------------------------------------------------
    def test_cpu_health_stats_times_serialization(self):

        # Construct a json representation of a CpuHealthStatsTimes model
        cpu_health_stats_times_model_json = {}
        cpu_health_stats_times_model_json['idle'] = 131397203
        cpu_health_stats_times_model_json['irq'] = 6068640
        cpu_health_stats_times_model_json['nice'] = 0
        cpu_health_stats_times_model_json['sys'] = 9652328
        cpu_health_stats_times_model_json['user'] = 4152187

        # Construct a model instance of CpuHealthStatsTimes by calling from_dict on the json representation
        cpu_health_stats_times_model = CpuHealthStatsTimes.from_dict(cpu_health_stats_times_model_json)
        assert cpu_health_stats_times_model != False

        # Construct a model instance of CpuHealthStatsTimes by calling from_dict on the json representation
        cpu_health_stats_times_model_dict = CpuHealthStatsTimes.from_dict(cpu_health_stats_times_model_json).__dict__
        cpu_health_stats_times_model2 = CpuHealthStatsTimes(**cpu_health_stats_times_model_dict)

        # Verify the model instances are equivalent
        assert cpu_health_stats_times_model == cpu_health_stats_times_model2

        # Convert model instance back to dict and verify no loss of data
        cpu_health_stats_times_model_json2 = cpu_health_stats_times_model.to_dict()
        assert cpu_health_stats_times_model_json2 == cpu_health_stats_times_model_json

#-----------------------------------------------------------------------------
# Test Class for CreateCaBodyConfigOverride
#-----------------------------------------------------------------------------
class TestCreateCaBodyConfigOverride():

    #--------------------------------------------------------
    # Test serialization/deserialization for CreateCaBodyConfigOverride
    #--------------------------------------------------------
    def test_create_ca_body_config_override_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_signing_profiles_ca_caconstraint_model = {} # ConfigCASigningProfilesCaCaconstraint
        config_ca_signing_profiles_ca_caconstraint_model['isca'] = True
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlen'] = 0
        config_ca_signing_profiles_ca_caconstraint_model['maxpathlenzero'] = True

        config_ca_db_tls_client_model = {} # ConfigCADbTlsClient
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        config_ca_intermediate_tls_client_model = {} # ConfigCAIntermediateTlsClient
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        config_ca_signing_profiles_ca_model = {} # ConfigCASigningProfilesCa
        config_ca_signing_profiles_ca_model['usage'] = ['cert sign']
        config_ca_signing_profiles_ca_model['expiry'] = '43800h'
        config_ca_signing_profiles_ca_model['caconstraint'] = config_ca_signing_profiles_ca_caconstraint_model

        config_ca_signing_profiles_tls_model = {} # ConfigCASigningProfilesTls
        config_ca_signing_profiles_tls_model['usage'] = ['cert sign']
        config_ca_signing_profiles_tls_model['expiry'] = '43800h'

        identity_attrs_model = {} # IdentityAttrs
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        config_ca_cfg_identities_model = {} # ConfigCACfgIdentities
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        config_ca_csr_ca_model = {} # ConfigCACsrCa
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        config_ca_csr_keyrequest_model = {} # ConfigCACsrKeyrequest
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        config_ca_csr_names_item_model = {} # ConfigCACsrNamesItem
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        config_ca_db_tls_model = {} # ConfigCADbTls
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        config_ca_intermediate_enrollment_model = {} # ConfigCAIntermediateEnrollment
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        config_ca_intermediate_parentserver_model = {} # ConfigCAIntermediateParentserver
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        config_ca_intermediate_tls_model = {} # ConfigCAIntermediateTls
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        config_ca_registry_identities_item_model = {} # ConfigCARegistryIdentitiesItem
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        config_ca_signing_default_model = {} # ConfigCASigningDefault
        config_ca_signing_default_model['usage'] = ['cert sign']
        config_ca_signing_default_model['expiry'] = '8760h'

        config_ca_signing_profiles_model = {} # ConfigCASigningProfiles
        config_ca_signing_profiles_model['ca'] = config_ca_signing_profiles_ca_model
        config_ca_signing_profiles_model['tls'] = config_ca_signing_profiles_tls_model

        config_ca_tls_clientauth_model = {} # ConfigCATlsClientauth
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_ca_affiliations_model = {} # ConfigCAAffiliations
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        config_ca_ca_model = {} # ConfigCACa
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        config_ca_cfg_model = {} # ConfigCACfg
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        config_ca_cors_model = {} # ConfigCACors
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        config_ca_crl_model = {} # ConfigCACrl
        config_ca_crl_model['expiry'] = '24h'

        config_ca_csr_model = {} # ConfigCACsr
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        config_ca_db_model = {} # ConfigCADb
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        config_ca_idemix_model = {} # ConfigCAIdemix
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        config_ca_intermediate_model = {} # ConfigCAIntermediate
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        config_ca_registry_model = {} # ConfigCARegistry
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        config_ca_signing_model = {} # ConfigCASigning
        config_ca_signing_model['default'] = config_ca_signing_default_model
        config_ca_signing_model['profiles'] = config_ca_signing_profiles_model

        config_ca_tls_model = {} # ConfigCATls
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        metrics_model = {} # Metrics
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        config_ca_create_model = {} # ConfigCACreate
        config_ca_create_model['cors'] = config_ca_cors_model
        config_ca_create_model['debug'] = False
        config_ca_create_model['crlsizelimit'] = 512000
        config_ca_create_model['tls'] = config_ca_tls_model
        config_ca_create_model['ca'] = config_ca_ca_model
        config_ca_create_model['crl'] = config_ca_crl_model
        config_ca_create_model['registry'] = config_ca_registry_model
        config_ca_create_model['db'] = config_ca_db_model
        config_ca_create_model['affiliations'] = config_ca_affiliations_model
        config_ca_create_model['csr'] = config_ca_csr_model
        config_ca_create_model['idemix'] = config_ca_idemix_model
        config_ca_create_model['BCCSP'] = bccsp_model
        config_ca_create_model['intermediate'] = config_ca_intermediate_model
        config_ca_create_model['cfg'] = config_ca_cfg_model
        config_ca_create_model['metrics'] = metrics_model
        config_ca_create_model['signing'] = config_ca_signing_model

        # Construct a json representation of a CreateCaBodyConfigOverride model
        create_ca_body_config_override_model_json = {}
        create_ca_body_config_override_model_json['ca'] = config_ca_create_model
        create_ca_body_config_override_model_json['tlsca'] = config_ca_create_model

        # Construct a model instance of CreateCaBodyConfigOverride by calling from_dict on the json representation
        create_ca_body_config_override_model = CreateCaBodyConfigOverride.from_dict(create_ca_body_config_override_model_json)
        assert create_ca_body_config_override_model != False

        # Construct a model instance of CreateCaBodyConfigOverride by calling from_dict on the json representation
        create_ca_body_config_override_model_dict = CreateCaBodyConfigOverride.from_dict(create_ca_body_config_override_model_json).__dict__
        create_ca_body_config_override_model2 = CreateCaBodyConfigOverride(**create_ca_body_config_override_model_dict)

        # Verify the model instances are equivalent
        assert create_ca_body_config_override_model == create_ca_body_config_override_model2

        # Convert model instance back to dict and verify no loss of data
        create_ca_body_config_override_model_json2 = create_ca_body_config_override_model.to_dict()
        assert create_ca_body_config_override_model_json2 == create_ca_body_config_override_model_json

#-----------------------------------------------------------------------------
# Test Class for CreateCaBodyResources
#-----------------------------------------------------------------------------
class TestCreateCaBodyResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for CreateCaBodyResources
    #--------------------------------------------------------
    def test_create_ca_body_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        resource_object_model = {} # ResourceObject
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a json representation of a CreateCaBodyResources model
        create_ca_body_resources_model_json = {}
        create_ca_body_resources_model_json['ca'] = resource_object_model

        # Construct a model instance of CreateCaBodyResources by calling from_dict on the json representation
        create_ca_body_resources_model = CreateCaBodyResources.from_dict(create_ca_body_resources_model_json)
        assert create_ca_body_resources_model != False

        # Construct a model instance of CreateCaBodyResources by calling from_dict on the json representation
        create_ca_body_resources_model_dict = CreateCaBodyResources.from_dict(create_ca_body_resources_model_json).__dict__
        create_ca_body_resources_model2 = CreateCaBodyResources(**create_ca_body_resources_model_dict)

        # Verify the model instances are equivalent
        assert create_ca_body_resources_model == create_ca_body_resources_model2

        # Convert model instance back to dict and verify no loss of data
        create_ca_body_resources_model_json2 = create_ca_body_resources_model.to_dict()
        assert create_ca_body_resources_model_json2 == create_ca_body_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for CreateCaBodyStorage
#-----------------------------------------------------------------------------
class TestCreateCaBodyStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for CreateCaBodyStorage
    #--------------------------------------------------------
    def test_create_ca_body_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a CreateCaBodyStorage model
        create_ca_body_storage_model_json = {}
        create_ca_body_storage_model_json['ca'] = storage_object_model

        # Construct a model instance of CreateCaBodyStorage by calling from_dict on the json representation
        create_ca_body_storage_model = CreateCaBodyStorage.from_dict(create_ca_body_storage_model_json)
        assert create_ca_body_storage_model != False

        # Construct a model instance of CreateCaBodyStorage by calling from_dict on the json representation
        create_ca_body_storage_model_dict = CreateCaBodyStorage.from_dict(create_ca_body_storage_model_json).__dict__
        create_ca_body_storage_model2 = CreateCaBodyStorage(**create_ca_body_storage_model_dict)

        # Verify the model instances are equivalent
        assert create_ca_body_storage_model == create_ca_body_storage_model2

        # Convert model instance back to dict and verify no loss of data
        create_ca_body_storage_model_json2 = create_ca_body_storage_model.to_dict()
        assert create_ca_body_storage_model_json2 == create_ca_body_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for CreateOrdererRaftBodyResources
#-----------------------------------------------------------------------------
class TestCreateOrdererRaftBodyResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for CreateOrdererRaftBodyResources
    #--------------------------------------------------------
    def test_create_orderer_raft_body_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        resource_object_model = {} # ResourceObject
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a json representation of a CreateOrdererRaftBodyResources model
        create_orderer_raft_body_resources_model_json = {}
        create_orderer_raft_body_resources_model_json['orderer'] = resource_object_model
        create_orderer_raft_body_resources_model_json['proxy'] = resource_object_model

        # Construct a model instance of CreateOrdererRaftBodyResources by calling from_dict on the json representation
        create_orderer_raft_body_resources_model = CreateOrdererRaftBodyResources.from_dict(create_orderer_raft_body_resources_model_json)
        assert create_orderer_raft_body_resources_model != False

        # Construct a model instance of CreateOrdererRaftBodyResources by calling from_dict on the json representation
        create_orderer_raft_body_resources_model_dict = CreateOrdererRaftBodyResources.from_dict(create_orderer_raft_body_resources_model_json).__dict__
        create_orderer_raft_body_resources_model2 = CreateOrdererRaftBodyResources(**create_orderer_raft_body_resources_model_dict)

        # Verify the model instances are equivalent
        assert create_orderer_raft_body_resources_model == create_orderer_raft_body_resources_model2

        # Convert model instance back to dict and verify no loss of data
        create_orderer_raft_body_resources_model_json2 = create_orderer_raft_body_resources_model.to_dict()
        assert create_orderer_raft_body_resources_model_json2 == create_orderer_raft_body_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for CreateOrdererRaftBodyStorage
#-----------------------------------------------------------------------------
class TestCreateOrdererRaftBodyStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for CreateOrdererRaftBodyStorage
    #--------------------------------------------------------
    def test_create_orderer_raft_body_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a CreateOrdererRaftBodyStorage model
        create_orderer_raft_body_storage_model_json = {}
        create_orderer_raft_body_storage_model_json['orderer'] = storage_object_model

        # Construct a model instance of CreateOrdererRaftBodyStorage by calling from_dict on the json representation
        create_orderer_raft_body_storage_model = CreateOrdererRaftBodyStorage.from_dict(create_orderer_raft_body_storage_model_json)
        assert create_orderer_raft_body_storage_model != False

        # Construct a model instance of CreateOrdererRaftBodyStorage by calling from_dict on the json representation
        create_orderer_raft_body_storage_model_dict = CreateOrdererRaftBodyStorage.from_dict(create_orderer_raft_body_storage_model_json).__dict__
        create_orderer_raft_body_storage_model2 = CreateOrdererRaftBodyStorage(**create_orderer_raft_body_storage_model_dict)

        # Verify the model instances are equivalent
        assert create_orderer_raft_body_storage_model == create_orderer_raft_body_storage_model2

        # Convert model instance back to dict and verify no loss of data
        create_orderer_raft_body_storage_model_json2 = create_orderer_raft_body_storage_model.to_dict()
        assert create_orderer_raft_body_storage_model_json2 == create_orderer_raft_body_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for CreatePeerBodyStorage
#-----------------------------------------------------------------------------
class TestCreatePeerBodyStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for CreatePeerBodyStorage
    #--------------------------------------------------------
    def test_create_peer_body_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a CreatePeerBodyStorage model
        create_peer_body_storage_model_json = {}
        create_peer_body_storage_model_json['peer'] = storage_object_model
        create_peer_body_storage_model_json['statedb'] = storage_object_model

        # Construct a model instance of CreatePeerBodyStorage by calling from_dict on the json representation
        create_peer_body_storage_model = CreatePeerBodyStorage.from_dict(create_peer_body_storage_model_json)
        assert create_peer_body_storage_model != False

        # Construct a model instance of CreatePeerBodyStorage by calling from_dict on the json representation
        create_peer_body_storage_model_dict = CreatePeerBodyStorage.from_dict(create_peer_body_storage_model_json).__dict__
        create_peer_body_storage_model2 = CreatePeerBodyStorage(**create_peer_body_storage_model_dict)

        # Verify the model instances are equivalent
        assert create_peer_body_storage_model == create_peer_body_storage_model2

        # Convert model instance back to dict and verify no loss of data
        create_peer_body_storage_model_json2 = create_peer_body_storage_model.to_dict()
        assert create_peer_body_storage_model_json2 == create_peer_body_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for CryptoEnrollmentComponent
#-----------------------------------------------------------------------------
class TestCryptoEnrollmentComponent():

    #--------------------------------------------------------
    # Test serialization/deserialization for CryptoEnrollmentComponent
    #--------------------------------------------------------
    def test_crypto_enrollment_component_serialization(self):

        # Construct a json representation of a CryptoEnrollmentComponent model
        crypto_enrollment_component_model_json = {}
        crypto_enrollment_component_model_json['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of CryptoEnrollmentComponent by calling from_dict on the json representation
        crypto_enrollment_component_model = CryptoEnrollmentComponent.from_dict(crypto_enrollment_component_model_json)
        assert crypto_enrollment_component_model != False

        # Construct a model instance of CryptoEnrollmentComponent by calling from_dict on the json representation
        crypto_enrollment_component_model_dict = CryptoEnrollmentComponent.from_dict(crypto_enrollment_component_model_json).__dict__
        crypto_enrollment_component_model2 = CryptoEnrollmentComponent(**crypto_enrollment_component_model_dict)

        # Verify the model instances are equivalent
        assert crypto_enrollment_component_model == crypto_enrollment_component_model2

        # Convert model instance back to dict and verify no loss of data
        crypto_enrollment_component_model_json2 = crypto_enrollment_component_model.to_dict()
        assert crypto_enrollment_component_model_json2 == crypto_enrollment_component_model_json

#-----------------------------------------------------------------------------
# Test Class for CryptoObject
#-----------------------------------------------------------------------------
class TestCryptoObject():

    #--------------------------------------------------------
    # Test serialization/deserialization for CryptoObject
    #--------------------------------------------------------
    def test_crypto_object_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        crypto_enrollment_component_model = {} # CryptoEnrollmentComponent
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        crypto_object_enrollment_ca_model = {} # CryptoObjectEnrollmentCa
        crypto_object_enrollment_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model['port'] = 7054
        crypto_object_enrollment_ca_model['name'] = 'ca'
        crypto_object_enrollment_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model['enroll_secret'] = 'password'

        crypto_object_enrollment_tlsca_model = {} # CryptoObjectEnrollmentTlsca
        crypto_object_enrollment_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model['port'] = 7054
        crypto_object_enrollment_tlsca_model['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model['csr_hosts'] = ['testString']

        msp_crypto_ca_model = {} # MspCryptoCa
        msp_crypto_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model['ca_intermediate_certs'] = ['testString']

        msp_crypto_comp_model = {} # MspCryptoComp
        msp_crypto_comp_model['ekey'] = 'testString'
        msp_crypto_comp_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model['tls_key'] = 'testString'
        msp_crypto_comp_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['client_auth'] = client_auth_model

        crypto_object_enrollment_model = {} # CryptoObjectEnrollment
        crypto_object_enrollment_model['component'] = crypto_enrollment_component_model
        crypto_object_enrollment_model['ca'] = crypto_object_enrollment_ca_model
        crypto_object_enrollment_model['tlsca'] = crypto_object_enrollment_tlsca_model

        crypto_object_msp_model = {} # CryptoObjectMsp
        crypto_object_msp_model['component'] = msp_crypto_comp_model
        crypto_object_msp_model['ca'] = msp_crypto_ca_model
        crypto_object_msp_model['tlsca'] = msp_crypto_ca_model

        # Construct a json representation of a CryptoObject model
        crypto_object_model_json = {}
        crypto_object_model_json['enrollment'] = crypto_object_enrollment_model
        crypto_object_model_json['msp'] = crypto_object_msp_model

        # Construct a model instance of CryptoObject by calling from_dict on the json representation
        crypto_object_model = CryptoObject.from_dict(crypto_object_model_json)
        assert crypto_object_model != False

        # Construct a model instance of CryptoObject by calling from_dict on the json representation
        crypto_object_model_dict = CryptoObject.from_dict(crypto_object_model_json).__dict__
        crypto_object_model2 = CryptoObject(**crypto_object_model_dict)

        # Verify the model instances are equivalent
        assert crypto_object_model == crypto_object_model2

        # Convert model instance back to dict and verify no loss of data
        crypto_object_model_json2 = crypto_object_model.to_dict()
        assert crypto_object_model_json2 == crypto_object_model_json

#-----------------------------------------------------------------------------
# Test Class for CryptoObjectEnrollment
#-----------------------------------------------------------------------------
class TestCryptoObjectEnrollment():

    #--------------------------------------------------------
    # Test serialization/deserialization for CryptoObjectEnrollment
    #--------------------------------------------------------
    def test_crypto_object_enrollment_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        crypto_enrollment_component_model = {} # CryptoEnrollmentComponent
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        crypto_object_enrollment_ca_model = {} # CryptoObjectEnrollmentCa
        crypto_object_enrollment_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model['port'] = 7054
        crypto_object_enrollment_ca_model['name'] = 'ca'
        crypto_object_enrollment_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model['enroll_secret'] = 'password'

        crypto_object_enrollment_tlsca_model = {} # CryptoObjectEnrollmentTlsca
        crypto_object_enrollment_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model['port'] = 7054
        crypto_object_enrollment_tlsca_model['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model['csr_hosts'] = ['testString']

        # Construct a json representation of a CryptoObjectEnrollment model
        crypto_object_enrollment_model_json = {}
        crypto_object_enrollment_model_json['component'] = crypto_enrollment_component_model
        crypto_object_enrollment_model_json['ca'] = crypto_object_enrollment_ca_model
        crypto_object_enrollment_model_json['tlsca'] = crypto_object_enrollment_tlsca_model

        # Construct a model instance of CryptoObjectEnrollment by calling from_dict on the json representation
        crypto_object_enrollment_model = CryptoObjectEnrollment.from_dict(crypto_object_enrollment_model_json)
        assert crypto_object_enrollment_model != False

        # Construct a model instance of CryptoObjectEnrollment by calling from_dict on the json representation
        crypto_object_enrollment_model_dict = CryptoObjectEnrollment.from_dict(crypto_object_enrollment_model_json).__dict__
        crypto_object_enrollment_model2 = CryptoObjectEnrollment(**crypto_object_enrollment_model_dict)

        # Verify the model instances are equivalent
        assert crypto_object_enrollment_model == crypto_object_enrollment_model2

        # Convert model instance back to dict and verify no loss of data
        crypto_object_enrollment_model_json2 = crypto_object_enrollment_model.to_dict()
        assert crypto_object_enrollment_model_json2 == crypto_object_enrollment_model_json

#-----------------------------------------------------------------------------
# Test Class for CryptoObjectEnrollmentCa
#-----------------------------------------------------------------------------
class TestCryptoObjectEnrollmentCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for CryptoObjectEnrollmentCa
    #--------------------------------------------------------
    def test_crypto_object_enrollment_ca_serialization(self):

        # Construct a json representation of a CryptoObjectEnrollmentCa model
        crypto_object_enrollment_ca_model_json = {}
        crypto_object_enrollment_ca_model_json['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_ca_model_json['port'] = 7054
        crypto_object_enrollment_ca_model_json['name'] = 'ca'
        crypto_object_enrollment_ca_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_ca_model_json['enroll_id'] = 'admin'
        crypto_object_enrollment_ca_model_json['enroll_secret'] = 'password'

        # Construct a model instance of CryptoObjectEnrollmentCa by calling from_dict on the json representation
        crypto_object_enrollment_ca_model = CryptoObjectEnrollmentCa.from_dict(crypto_object_enrollment_ca_model_json)
        assert crypto_object_enrollment_ca_model != False

        # Construct a model instance of CryptoObjectEnrollmentCa by calling from_dict on the json representation
        crypto_object_enrollment_ca_model_dict = CryptoObjectEnrollmentCa.from_dict(crypto_object_enrollment_ca_model_json).__dict__
        crypto_object_enrollment_ca_model2 = CryptoObjectEnrollmentCa(**crypto_object_enrollment_ca_model_dict)

        # Verify the model instances are equivalent
        assert crypto_object_enrollment_ca_model == crypto_object_enrollment_ca_model2

        # Convert model instance back to dict and verify no loss of data
        crypto_object_enrollment_ca_model_json2 = crypto_object_enrollment_ca_model.to_dict()
        assert crypto_object_enrollment_ca_model_json2 == crypto_object_enrollment_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for CryptoObjectEnrollmentTlsca
#-----------------------------------------------------------------------------
class TestCryptoObjectEnrollmentTlsca():

    #--------------------------------------------------------
    # Test serialization/deserialization for CryptoObjectEnrollmentTlsca
    #--------------------------------------------------------
    def test_crypto_object_enrollment_tlsca_serialization(self):

        # Construct a json representation of a CryptoObjectEnrollmentTlsca model
        crypto_object_enrollment_tlsca_model_json = {}
        crypto_object_enrollment_tlsca_model_json['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        crypto_object_enrollment_tlsca_model_json['port'] = 7054
        crypto_object_enrollment_tlsca_model_json['name'] = 'tlsca'
        crypto_object_enrollment_tlsca_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        crypto_object_enrollment_tlsca_model_json['enroll_id'] = 'admin'
        crypto_object_enrollment_tlsca_model_json['enroll_secret'] = 'password'
        crypto_object_enrollment_tlsca_model_json['csr_hosts'] = ['testString']

        # Construct a model instance of CryptoObjectEnrollmentTlsca by calling from_dict on the json representation
        crypto_object_enrollment_tlsca_model = CryptoObjectEnrollmentTlsca.from_dict(crypto_object_enrollment_tlsca_model_json)
        assert crypto_object_enrollment_tlsca_model != False

        # Construct a model instance of CryptoObjectEnrollmentTlsca by calling from_dict on the json representation
        crypto_object_enrollment_tlsca_model_dict = CryptoObjectEnrollmentTlsca.from_dict(crypto_object_enrollment_tlsca_model_json).__dict__
        crypto_object_enrollment_tlsca_model2 = CryptoObjectEnrollmentTlsca(**crypto_object_enrollment_tlsca_model_dict)

        # Verify the model instances are equivalent
        assert crypto_object_enrollment_tlsca_model == crypto_object_enrollment_tlsca_model2

        # Convert model instance back to dict and verify no loss of data
        crypto_object_enrollment_tlsca_model_json2 = crypto_object_enrollment_tlsca_model.to_dict()
        assert crypto_object_enrollment_tlsca_model_json2 == crypto_object_enrollment_tlsca_model_json

#-----------------------------------------------------------------------------
# Test Class for CryptoObjectMsp
#-----------------------------------------------------------------------------
class TestCryptoObjectMsp():

    #--------------------------------------------------------
    # Test serialization/deserialization for CryptoObjectMsp
    #--------------------------------------------------------
    def test_crypto_object_msp_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        msp_crypto_ca_model = {} # MspCryptoCa
        msp_crypto_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model['ca_intermediate_certs'] = ['testString']

        msp_crypto_comp_model = {} # MspCryptoComp
        msp_crypto_comp_model['ekey'] = 'testString'
        msp_crypto_comp_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model['tls_key'] = 'testString'
        msp_crypto_comp_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model['client_auth'] = client_auth_model

        # Construct a json representation of a CryptoObjectMsp model
        crypto_object_msp_model_json = {}
        crypto_object_msp_model_json['component'] = msp_crypto_comp_model
        crypto_object_msp_model_json['ca'] = msp_crypto_ca_model
        crypto_object_msp_model_json['tlsca'] = msp_crypto_ca_model

        # Construct a model instance of CryptoObjectMsp by calling from_dict on the json representation
        crypto_object_msp_model = CryptoObjectMsp.from_dict(crypto_object_msp_model_json)
        assert crypto_object_msp_model != False

        # Construct a model instance of CryptoObjectMsp by calling from_dict on the json representation
        crypto_object_msp_model_dict = CryptoObjectMsp.from_dict(crypto_object_msp_model_json).__dict__
        crypto_object_msp_model2 = CryptoObjectMsp(**crypto_object_msp_model_dict)

        # Verify the model instances are equivalent
        assert crypto_object_msp_model == crypto_object_msp_model2

        # Convert model instance back to dict and verify no loss of data
        crypto_object_msp_model_json2 = crypto_object_msp_model.to_dict()
        assert crypto_object_msp_model_json2 == crypto_object_msp_model_json

#-----------------------------------------------------------------------------
# Test Class for DeleteAllNotificationsResponse
#-----------------------------------------------------------------------------
class TestDeleteAllNotificationsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for DeleteAllNotificationsResponse
    #--------------------------------------------------------
    def test_delete_all_notifications_response_serialization(self):

        # Construct a json representation of a DeleteAllNotificationsResponse model
        delete_all_notifications_response_model_json = {}
        delete_all_notifications_response_model_json['message'] = 'ok'
        delete_all_notifications_response_model_json['details'] = 'deleted 101 notification(s)'

        # Construct a model instance of DeleteAllNotificationsResponse by calling from_dict on the json representation
        delete_all_notifications_response_model = DeleteAllNotificationsResponse.from_dict(delete_all_notifications_response_model_json)
        assert delete_all_notifications_response_model != False

        # Construct a model instance of DeleteAllNotificationsResponse by calling from_dict on the json representation
        delete_all_notifications_response_model_dict = DeleteAllNotificationsResponse.from_dict(delete_all_notifications_response_model_json).__dict__
        delete_all_notifications_response_model2 = DeleteAllNotificationsResponse(**delete_all_notifications_response_model_dict)

        # Verify the model instances are equivalent
        assert delete_all_notifications_response_model == delete_all_notifications_response_model2

        # Convert model instance back to dict and verify no loss of data
        delete_all_notifications_response_model_json2 = delete_all_notifications_response_model.to_dict()
        assert delete_all_notifications_response_model_json2 == delete_all_notifications_response_model_json

#-----------------------------------------------------------------------------
# Test Class for DeleteAllSessionsResponse
#-----------------------------------------------------------------------------
class TestDeleteAllSessionsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for DeleteAllSessionsResponse
    #--------------------------------------------------------
    def test_delete_all_sessions_response_serialization(self):

        # Construct a json representation of a DeleteAllSessionsResponse model
        delete_all_sessions_response_model_json = {}
        delete_all_sessions_response_model_json['message'] = 'delete submitted'

        # Construct a model instance of DeleteAllSessionsResponse by calling from_dict on the json representation
        delete_all_sessions_response_model = DeleteAllSessionsResponse.from_dict(delete_all_sessions_response_model_json)
        assert delete_all_sessions_response_model != False

        # Construct a model instance of DeleteAllSessionsResponse by calling from_dict on the json representation
        delete_all_sessions_response_model_dict = DeleteAllSessionsResponse.from_dict(delete_all_sessions_response_model_json).__dict__
        delete_all_sessions_response_model2 = DeleteAllSessionsResponse(**delete_all_sessions_response_model_dict)

        # Verify the model instances are equivalent
        assert delete_all_sessions_response_model == delete_all_sessions_response_model2

        # Convert model instance back to dict and verify no loss of data
        delete_all_sessions_response_model_json2 = delete_all_sessions_response_model.to_dict()
        assert delete_all_sessions_response_model_json2 == delete_all_sessions_response_model_json

#-----------------------------------------------------------------------------
# Test Class for DeleteComponentResponse
#-----------------------------------------------------------------------------
class TestDeleteComponentResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for DeleteComponentResponse
    #--------------------------------------------------------
    def test_delete_component_response_serialization(self):

        # Construct a json representation of a DeleteComponentResponse model
        delete_component_response_model_json = {}
        delete_component_response_model_json['message'] = 'deleted'
        delete_component_response_model_json['type'] = 'fabric-peer'
        delete_component_response_model_json['id'] = 'component-1'
        delete_component_response_model_json['display_name'] = 'My Peer'

        # Construct a model instance of DeleteComponentResponse by calling from_dict on the json representation
        delete_component_response_model = DeleteComponentResponse.from_dict(delete_component_response_model_json)
        assert delete_component_response_model != False

        # Construct a model instance of DeleteComponentResponse by calling from_dict on the json representation
        delete_component_response_model_dict = DeleteComponentResponse.from_dict(delete_component_response_model_json).__dict__
        delete_component_response_model2 = DeleteComponentResponse(**delete_component_response_model_dict)

        # Verify the model instances are equivalent
        assert delete_component_response_model == delete_component_response_model2

        # Convert model instance back to dict and verify no loss of data
        delete_component_response_model_json2 = delete_component_response_model.to_dict()
        assert delete_component_response_model_json2 == delete_component_response_model_json

#-----------------------------------------------------------------------------
# Test Class for DeleteMultiComponentsResponse
#-----------------------------------------------------------------------------
class TestDeleteMultiComponentsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for DeleteMultiComponentsResponse
    #--------------------------------------------------------
    def test_delete_multi_components_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        delete_component_response_model = {} # DeleteComponentResponse
        delete_component_response_model['message'] = 'deleted'
        delete_component_response_model['type'] = 'fabric-peer'
        delete_component_response_model['id'] = 'component-1'
        delete_component_response_model['display_name'] = 'My Peer'

        # Construct a json representation of a DeleteMultiComponentsResponse model
        delete_multi_components_response_model_json = {}
        delete_multi_components_response_model_json['deleted'] = [delete_component_response_model]

        # Construct a model instance of DeleteMultiComponentsResponse by calling from_dict on the json representation
        delete_multi_components_response_model = DeleteMultiComponentsResponse.from_dict(delete_multi_components_response_model_json)
        assert delete_multi_components_response_model != False

        # Construct a model instance of DeleteMultiComponentsResponse by calling from_dict on the json representation
        delete_multi_components_response_model_dict = DeleteMultiComponentsResponse.from_dict(delete_multi_components_response_model_json).__dict__
        delete_multi_components_response_model2 = DeleteMultiComponentsResponse(**delete_multi_components_response_model_dict)

        # Verify the model instances are equivalent
        assert delete_multi_components_response_model == delete_multi_components_response_model2

        # Convert model instance back to dict and verify no loss of data
        delete_multi_components_response_model_json2 = delete_multi_components_response_model.to_dict()
        assert delete_multi_components_response_model_json2 == delete_multi_components_response_model_json

#-----------------------------------------------------------------------------
# Test Class for DeleteSignatureCollectionResponse
#-----------------------------------------------------------------------------
class TestDeleteSignatureCollectionResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for DeleteSignatureCollectionResponse
    #--------------------------------------------------------
    def test_delete_signature_collection_response_serialization(self):

        # Construct a json representation of a DeleteSignatureCollectionResponse model
        delete_signature_collection_response_model_json = {}
        delete_signature_collection_response_model_json['message'] = 'ok'
        delete_signature_collection_response_model_json['tx_id'] = 'abcde'

        # Construct a model instance of DeleteSignatureCollectionResponse by calling from_dict on the json representation
        delete_signature_collection_response_model = DeleteSignatureCollectionResponse.from_dict(delete_signature_collection_response_model_json)
        assert delete_signature_collection_response_model != False

        # Construct a model instance of DeleteSignatureCollectionResponse by calling from_dict on the json representation
        delete_signature_collection_response_model_dict = DeleteSignatureCollectionResponse.from_dict(delete_signature_collection_response_model_json).__dict__
        delete_signature_collection_response_model2 = DeleteSignatureCollectionResponse(**delete_signature_collection_response_model_dict)

        # Verify the model instances are equivalent
        assert delete_signature_collection_response_model == delete_signature_collection_response_model2

        # Convert model instance back to dict and verify no loss of data
        delete_signature_collection_response_model_json2 = delete_signature_collection_response_model.to_dict()
        assert delete_signature_collection_response_model_json2 == delete_signature_collection_response_model_json

#-----------------------------------------------------------------------------
# Test Class for EditAdminCertsResponse
#-----------------------------------------------------------------------------
class TestEditAdminCertsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for EditAdminCertsResponse
    #--------------------------------------------------------
    def test_edit_admin_certs_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        edit_admin_certs_response_set_admin_certs_item_model = {} # EditAdminCertsResponseSetAdminCertsItem
        edit_admin_certs_response_set_admin_certs_item_model['base_64_pem'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        edit_admin_certs_response_set_admin_certs_item_model['issuer'] = '/C=US/ST=North Carolina/O=Hyperledger/OU=Fabric/CN=fabric-ca-server'
        edit_admin_certs_response_set_admin_certs_item_model['not_after_ts'] = 1597770420000
        edit_admin_certs_response_set_admin_certs_item_model['not_before_ts'] = 1566234120000
        edit_admin_certs_response_set_admin_certs_item_model['serial_number_hex'] = '649a1206fd0bc8be994886dd715cecb0a7a21276'
        edit_admin_certs_response_set_admin_certs_item_model['signature_algorithm'] = 'SHA256withECDSA'
        edit_admin_certs_response_set_admin_certs_item_model['subject'] = '/OU=client/CN=admin'
        edit_admin_certs_response_set_admin_certs_item_model['X509_version'] = 3
        edit_admin_certs_response_set_admin_certs_item_model['time_left'] = '10 hrs'

        # Construct a json representation of a EditAdminCertsResponse model
        edit_admin_certs_response_model_json = {}
        edit_admin_certs_response_model_json['changes_made'] = 1
        edit_admin_certs_response_model_json['set_admin_certs'] = [edit_admin_certs_response_set_admin_certs_item_model]

        # Construct a model instance of EditAdminCertsResponse by calling from_dict on the json representation
        edit_admin_certs_response_model = EditAdminCertsResponse.from_dict(edit_admin_certs_response_model_json)
        assert edit_admin_certs_response_model != False

        # Construct a model instance of EditAdminCertsResponse by calling from_dict on the json representation
        edit_admin_certs_response_model_dict = EditAdminCertsResponse.from_dict(edit_admin_certs_response_model_json).__dict__
        edit_admin_certs_response_model2 = EditAdminCertsResponse(**edit_admin_certs_response_model_dict)

        # Verify the model instances are equivalent
        assert edit_admin_certs_response_model == edit_admin_certs_response_model2

        # Convert model instance back to dict and verify no loss of data
        edit_admin_certs_response_model_json2 = edit_admin_certs_response_model.to_dict()
        assert edit_admin_certs_response_model_json2 == edit_admin_certs_response_model_json

#-----------------------------------------------------------------------------
# Test Class for EditAdminCertsResponseSetAdminCertsItem
#-----------------------------------------------------------------------------
class TestEditAdminCertsResponseSetAdminCertsItem():

    #--------------------------------------------------------
    # Test serialization/deserialization for EditAdminCertsResponseSetAdminCertsItem
    #--------------------------------------------------------
    def test_edit_admin_certs_response_set_admin_certs_item_serialization(self):

        # Construct a json representation of a EditAdminCertsResponseSetAdminCertsItem model
        edit_admin_certs_response_set_admin_certs_item_model_json = {}
        edit_admin_certs_response_set_admin_certs_item_model_json['base_64_pem'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        edit_admin_certs_response_set_admin_certs_item_model_json['issuer'] = '/C=US/ST=North Carolina/O=Hyperledger/OU=Fabric/CN=fabric-ca-server'
        edit_admin_certs_response_set_admin_certs_item_model_json['not_after_ts'] = 1597770420000
        edit_admin_certs_response_set_admin_certs_item_model_json['not_before_ts'] = 1566234120000
        edit_admin_certs_response_set_admin_certs_item_model_json['serial_number_hex'] = '649a1206fd0bc8be994886dd715cecb0a7a21276'
        edit_admin_certs_response_set_admin_certs_item_model_json['signature_algorithm'] = 'SHA256withECDSA'
        edit_admin_certs_response_set_admin_certs_item_model_json['subject'] = '/OU=client/CN=admin'
        edit_admin_certs_response_set_admin_certs_item_model_json['X509_version'] = 3
        edit_admin_certs_response_set_admin_certs_item_model_json['time_left'] = '10 hrs'

        # Construct a model instance of EditAdminCertsResponseSetAdminCertsItem by calling from_dict on the json representation
        edit_admin_certs_response_set_admin_certs_item_model = EditAdminCertsResponseSetAdminCertsItem.from_dict(edit_admin_certs_response_set_admin_certs_item_model_json)
        assert edit_admin_certs_response_set_admin_certs_item_model != False

        # Construct a model instance of EditAdminCertsResponseSetAdminCertsItem by calling from_dict on the json representation
        edit_admin_certs_response_set_admin_certs_item_model_dict = EditAdminCertsResponseSetAdminCertsItem.from_dict(edit_admin_certs_response_set_admin_certs_item_model_json).__dict__
        edit_admin_certs_response_set_admin_certs_item_model2 = EditAdminCertsResponseSetAdminCertsItem(**edit_admin_certs_response_set_admin_certs_item_model_dict)

        # Verify the model instances are equivalent
        assert edit_admin_certs_response_set_admin_certs_item_model == edit_admin_certs_response_set_admin_certs_item_model2

        # Convert model instance back to dict and verify no loss of data
        edit_admin_certs_response_set_admin_certs_item_model_json2 = edit_admin_certs_response_set_admin_certs_item_model.to_dict()
        assert edit_admin_certs_response_set_admin_certs_item_model_json2 == edit_admin_certs_response_set_admin_certs_item_model_json

#-----------------------------------------------------------------------------
# Test Class for EditLogSettingsBody
#-----------------------------------------------------------------------------
class TestEditLogSettingsBody():

    #--------------------------------------------------------
    # Test serialization/deserialization for EditLogSettingsBody
    #--------------------------------------------------------
    def test_edit_log_settings_body_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        logging_settings_client_model = {} # LoggingSettingsClient
        logging_settings_client_model['enabled'] = True
        logging_settings_client_model['level'] = 'silly'
        logging_settings_client_model['unique_name'] = False

        logging_settings_server_model = {} # LoggingSettingsServer
        logging_settings_server_model['enabled'] = True
        logging_settings_server_model['level'] = 'silly'
        logging_settings_server_model['unique_name'] = False

        # Construct a json representation of a EditLogSettingsBody model
        edit_log_settings_body_model_json = {}
        edit_log_settings_body_model_json['client'] = logging_settings_client_model
        edit_log_settings_body_model_json['server'] = logging_settings_server_model

        # Construct a model instance of EditLogSettingsBody by calling from_dict on the json representation
        edit_log_settings_body_model = EditLogSettingsBody.from_dict(edit_log_settings_body_model_json)
        assert edit_log_settings_body_model != False

        # Construct a model instance of EditLogSettingsBody by calling from_dict on the json representation
        edit_log_settings_body_model_dict = EditLogSettingsBody.from_dict(edit_log_settings_body_model_json).__dict__
        edit_log_settings_body_model2 = EditLogSettingsBody(**edit_log_settings_body_model_dict)

        # Verify the model instances are equivalent
        assert edit_log_settings_body_model == edit_log_settings_body_model2

        # Convert model instance back to dict and verify no loss of data
        edit_log_settings_body_model_json2 = edit_log_settings_body_model.to_dict()
        assert edit_log_settings_body_model_json2 == edit_log_settings_body_model_json

#-----------------------------------------------------------------------------
# Test Class for EditSettingsBodyInactivityTimeouts
#-----------------------------------------------------------------------------
class TestEditSettingsBodyInactivityTimeouts():

    #--------------------------------------------------------
    # Test serialization/deserialization for EditSettingsBodyInactivityTimeouts
    #--------------------------------------------------------
    def test_edit_settings_body_inactivity_timeouts_serialization(self):

        # Construct a json representation of a EditSettingsBodyInactivityTimeouts model
        edit_settings_body_inactivity_timeouts_model_json = {}
        edit_settings_body_inactivity_timeouts_model_json['enabled'] = False
        edit_settings_body_inactivity_timeouts_model_json['max_idle_time'] = 90000

        # Construct a model instance of EditSettingsBodyInactivityTimeouts by calling from_dict on the json representation
        edit_settings_body_inactivity_timeouts_model = EditSettingsBodyInactivityTimeouts.from_dict(edit_settings_body_inactivity_timeouts_model_json)
        assert edit_settings_body_inactivity_timeouts_model != False

        # Construct a model instance of EditSettingsBodyInactivityTimeouts by calling from_dict on the json representation
        edit_settings_body_inactivity_timeouts_model_dict = EditSettingsBodyInactivityTimeouts.from_dict(edit_settings_body_inactivity_timeouts_model_json).__dict__
        edit_settings_body_inactivity_timeouts_model2 = EditSettingsBodyInactivityTimeouts(**edit_settings_body_inactivity_timeouts_model_dict)

        # Verify the model instances are equivalent
        assert edit_settings_body_inactivity_timeouts_model == edit_settings_body_inactivity_timeouts_model2

        # Convert model instance back to dict and verify no loss of data
        edit_settings_body_inactivity_timeouts_model_json2 = edit_settings_body_inactivity_timeouts_model.to_dict()
        assert edit_settings_body_inactivity_timeouts_model_json2 == edit_settings_body_inactivity_timeouts_model_json

#-----------------------------------------------------------------------------
# Test Class for FabVersionObject
#-----------------------------------------------------------------------------
class TestFabVersionObject():

    #--------------------------------------------------------
    # Test serialization/deserialization for FabVersionObject
    #--------------------------------------------------------
    def test_fab_version_object_serialization(self):

        # Construct a json representation of a FabVersionObject model
        fab_version_object_model_json = {}
        fab_version_object_model_json['default'] = True
        fab_version_object_model_json['version'] = '1.4.6-2'
        fab_version_object_model_json['image'] = { 'foo': 'bar' }

        # Construct a model instance of FabVersionObject by calling from_dict on the json representation
        fab_version_object_model = FabVersionObject.from_dict(fab_version_object_model_json)
        assert fab_version_object_model != False

        # Construct a model instance of FabVersionObject by calling from_dict on the json representation
        fab_version_object_model_dict = FabVersionObject.from_dict(fab_version_object_model_json).__dict__
        fab_version_object_model2 = FabVersionObject(**fab_version_object_model_dict)

        # Verify the model instances are equivalent
        assert fab_version_object_model == fab_version_object_model2

        # Convert model instance back to dict and verify no loss of data
        fab_version_object_model_json2 = fab_version_object_model.to_dict()
        assert fab_version_object_model_json2 == fab_version_object_model_json

#-----------------------------------------------------------------------------
# Test Class for FabricVersionDictionary
#-----------------------------------------------------------------------------
class TestFabricVersionDictionary():

    #--------------------------------------------------------
    # Test serialization/deserialization for FabricVersionDictionary
    #--------------------------------------------------------
    def test_fabric_version_dictionary_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        fab_version_object_model = {} # FabVersionObject
        fab_version_object_model['default'] = True
        fab_version_object_model['version'] = '1.4.6-2'
        fab_version_object_model['image'] = { 'foo': 'bar' }

        # Construct a json representation of a FabricVersionDictionary model
        fabric_version_dictionary_model_json = {}
        fabric_version_dictionary_model_json['1.4.6-2'] = fab_version_object_model
        fabric_version_dictionary_model_json['2.1.0-0'] = fab_version_object_model
        fabric_version_dictionary_model_json['foo'] = { 'foo': 'bar' }

        # Construct a model instance of FabricVersionDictionary by calling from_dict on the json representation
        fabric_version_dictionary_model = FabricVersionDictionary.from_dict(fabric_version_dictionary_model_json)
        assert fabric_version_dictionary_model != False

        # Construct a model instance of FabricVersionDictionary by calling from_dict on the json representation
        fabric_version_dictionary_model_dict = FabricVersionDictionary.from_dict(fabric_version_dictionary_model_json).__dict__
        fabric_version_dictionary_model2 = FabricVersionDictionary(**fabric_version_dictionary_model_dict)

        # Verify the model instances are equivalent
        assert fabric_version_dictionary_model == fabric_version_dictionary_model2

        # Convert model instance back to dict and verify no loss of data
        fabric_version_dictionary_model_json2 = fabric_version_dictionary_model.to_dict()
        assert fabric_version_dictionary_model_json2 == fabric_version_dictionary_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponse
#-----------------------------------------------------------------------------
class TestGenericComponentResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponse
    #--------------------------------------------------------
    def test_generic_component_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_component_response_msp_ca_model = {} # GenericComponentResponseMspCa
        generic_component_response_msp_ca_model['name'] = 'org1CA'
        generic_component_response_msp_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_component_response_msp_component_model = {} # GenericComponentResponseMspComponent
        generic_component_response_msp_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_component_response_msp_tlsca_model = {} # GenericComponentResponseMspTlsca
        generic_component_response_msp_tlsca_model['name'] = 'org1tlsCA'
        generic_component_response_msp_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        generic_component_response_msp_model = {} # GenericComponentResponseMsp
        generic_component_response_msp_model['ca'] = generic_component_response_msp_ca_model
        generic_component_response_msp_model['tlsca'] = generic_component_response_msp_tlsca_model
        generic_component_response_msp_model['component'] = generic_component_response_msp_component_model

        generic_component_response_resources_model = {} # GenericComponentResponseResources
        generic_component_response_resources_model['ca'] = generic_resources_model
        generic_component_response_resources_model['peer'] = generic_resources_model
        generic_component_response_resources_model['orderer'] = generic_resources_model
        generic_component_response_resources_model['proxy'] = generic_resources_model
        generic_component_response_resources_model['statedb'] = generic_resources_model

        generic_component_response_storage_model = {} # GenericComponentResponseStorage
        generic_component_response_storage_model['ca'] = storage_object_model
        generic_component_response_storage_model['peer'] = storage_object_model
        generic_component_response_storage_model['orderer'] = storage_object_model
        generic_component_response_storage_model['statedb'] = storage_object_model

        node_ou_general_model = {} # NodeOuGeneral
        node_ou_general_model['enabled'] = True

        # Construct a json representation of a GenericComponentResponse model
        generic_component_response_model_json = {}
        generic_component_response_model_json['id'] = 'myca-2'
        generic_component_response_model_json['type'] = 'fabric-ca'
        generic_component_response_model_json['display_name'] = 'Example CA'
        generic_component_response_model_json['grpcwp_url'] = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        generic_component_response_model_json['api_url'] = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        generic_component_response_model_json['operations_url'] = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        generic_component_response_model_json['msp'] = generic_component_response_msp_model
        generic_component_response_model_json['msp_id'] = 'Org1'
        generic_component_response_model_json['location'] = 'ibmcloud'
        generic_component_response_model_json['node_ou'] = node_ou_general_model
        generic_component_response_model_json['resources'] = generic_component_response_resources_model
        generic_component_response_model_json['scheme_version'] = 'v1'
        generic_component_response_model_json['state_db'] = 'couchdb'
        generic_component_response_model_json['storage'] = generic_component_response_storage_model
        generic_component_response_model_json['timestamp'] = 1537262855753
        generic_component_response_model_json['tags'] = ['fabric-ca']
        generic_component_response_model_json['version'] = '1.4.6-1'
        generic_component_response_model_json['zone'] = '-'

        # Construct a model instance of GenericComponentResponse by calling from_dict on the json representation
        generic_component_response_model = GenericComponentResponse.from_dict(generic_component_response_model_json)
        assert generic_component_response_model != False

        # Construct a model instance of GenericComponentResponse by calling from_dict on the json representation
        generic_component_response_model_dict = GenericComponentResponse.from_dict(generic_component_response_model_json).__dict__
        generic_component_response_model2 = GenericComponentResponse(**generic_component_response_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_model == generic_component_response_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_model_json2 = generic_component_response_model.to_dict()
        assert generic_component_response_model_json2 == generic_component_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponseMsp
#-----------------------------------------------------------------------------
class TestGenericComponentResponseMsp():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponseMsp
    #--------------------------------------------------------
    def test_generic_component_response_msp_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_component_response_msp_ca_model = {} # GenericComponentResponseMspCa
        generic_component_response_msp_ca_model['name'] = 'org1CA'
        generic_component_response_msp_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_component_response_msp_component_model = {} # GenericComponentResponseMspComponent
        generic_component_response_msp_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_component_response_msp_tlsca_model = {} # GenericComponentResponseMspTlsca
        generic_component_response_msp_tlsca_model['name'] = 'org1tlsCA'
        generic_component_response_msp_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a json representation of a GenericComponentResponseMsp model
        generic_component_response_msp_model_json = {}
        generic_component_response_msp_model_json['ca'] = generic_component_response_msp_ca_model
        generic_component_response_msp_model_json['tlsca'] = generic_component_response_msp_tlsca_model
        generic_component_response_msp_model_json['component'] = generic_component_response_msp_component_model

        # Construct a model instance of GenericComponentResponseMsp by calling from_dict on the json representation
        generic_component_response_msp_model = GenericComponentResponseMsp.from_dict(generic_component_response_msp_model_json)
        assert generic_component_response_msp_model != False

        # Construct a model instance of GenericComponentResponseMsp by calling from_dict on the json representation
        generic_component_response_msp_model_dict = GenericComponentResponseMsp.from_dict(generic_component_response_msp_model_json).__dict__
        generic_component_response_msp_model2 = GenericComponentResponseMsp(**generic_component_response_msp_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_msp_model == generic_component_response_msp_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_msp_model_json2 = generic_component_response_msp_model.to_dict()
        assert generic_component_response_msp_model_json2 == generic_component_response_msp_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponseMspCa
#-----------------------------------------------------------------------------
class TestGenericComponentResponseMspCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponseMspCa
    #--------------------------------------------------------
    def test_generic_component_response_msp_ca_serialization(self):

        # Construct a json representation of a GenericComponentResponseMspCa model
        generic_component_response_msp_ca_model_json = {}
        generic_component_response_msp_ca_model_json['name'] = 'org1CA'
        generic_component_response_msp_ca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of GenericComponentResponseMspCa by calling from_dict on the json representation
        generic_component_response_msp_ca_model = GenericComponentResponseMspCa.from_dict(generic_component_response_msp_ca_model_json)
        assert generic_component_response_msp_ca_model != False

        # Construct a model instance of GenericComponentResponseMspCa by calling from_dict on the json representation
        generic_component_response_msp_ca_model_dict = GenericComponentResponseMspCa.from_dict(generic_component_response_msp_ca_model_json).__dict__
        generic_component_response_msp_ca_model2 = GenericComponentResponseMspCa(**generic_component_response_msp_ca_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_msp_ca_model == generic_component_response_msp_ca_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_msp_ca_model_json2 = generic_component_response_msp_ca_model.to_dict()
        assert generic_component_response_msp_ca_model_json2 == generic_component_response_msp_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponseMspComponent
#-----------------------------------------------------------------------------
class TestGenericComponentResponseMspComponent():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponseMspComponent
    #--------------------------------------------------------
    def test_generic_component_response_msp_component_serialization(self):

        # Construct a json representation of a GenericComponentResponseMspComponent model
        generic_component_response_msp_component_model_json = {}
        generic_component_response_msp_component_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model_json['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model_json['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of GenericComponentResponseMspComponent by calling from_dict on the json representation
        generic_component_response_msp_component_model = GenericComponentResponseMspComponent.from_dict(generic_component_response_msp_component_model_json)
        assert generic_component_response_msp_component_model != False

        # Construct a model instance of GenericComponentResponseMspComponent by calling from_dict on the json representation
        generic_component_response_msp_component_model_dict = GenericComponentResponseMspComponent.from_dict(generic_component_response_msp_component_model_json).__dict__
        generic_component_response_msp_component_model2 = GenericComponentResponseMspComponent(**generic_component_response_msp_component_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_msp_component_model == generic_component_response_msp_component_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_msp_component_model_json2 = generic_component_response_msp_component_model.to_dict()
        assert generic_component_response_msp_component_model_json2 == generic_component_response_msp_component_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponseMspTlsca
#-----------------------------------------------------------------------------
class TestGenericComponentResponseMspTlsca():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponseMspTlsca
    #--------------------------------------------------------
    def test_generic_component_response_msp_tlsca_serialization(self):

        # Construct a json representation of a GenericComponentResponseMspTlsca model
        generic_component_response_msp_tlsca_model_json = {}
        generic_component_response_msp_tlsca_model_json['name'] = 'org1tlsCA'
        generic_component_response_msp_tlsca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of GenericComponentResponseMspTlsca by calling from_dict on the json representation
        generic_component_response_msp_tlsca_model = GenericComponentResponseMspTlsca.from_dict(generic_component_response_msp_tlsca_model_json)
        assert generic_component_response_msp_tlsca_model != False

        # Construct a model instance of GenericComponentResponseMspTlsca by calling from_dict on the json representation
        generic_component_response_msp_tlsca_model_dict = GenericComponentResponseMspTlsca.from_dict(generic_component_response_msp_tlsca_model_json).__dict__
        generic_component_response_msp_tlsca_model2 = GenericComponentResponseMspTlsca(**generic_component_response_msp_tlsca_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_msp_tlsca_model == generic_component_response_msp_tlsca_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_msp_tlsca_model_json2 = generic_component_response_msp_tlsca_model.to_dict()
        assert generic_component_response_msp_tlsca_model_json2 == generic_component_response_msp_tlsca_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponseResources
#-----------------------------------------------------------------------------
class TestGenericComponentResponseResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponseResources
    #--------------------------------------------------------
    def test_generic_component_response_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        # Construct a json representation of a GenericComponentResponseResources model
        generic_component_response_resources_model_json = {}
        generic_component_response_resources_model_json['ca'] = generic_resources_model
        generic_component_response_resources_model_json['peer'] = generic_resources_model
        generic_component_response_resources_model_json['orderer'] = generic_resources_model
        generic_component_response_resources_model_json['proxy'] = generic_resources_model
        generic_component_response_resources_model_json['statedb'] = generic_resources_model

        # Construct a model instance of GenericComponentResponseResources by calling from_dict on the json representation
        generic_component_response_resources_model = GenericComponentResponseResources.from_dict(generic_component_response_resources_model_json)
        assert generic_component_response_resources_model != False

        # Construct a model instance of GenericComponentResponseResources by calling from_dict on the json representation
        generic_component_response_resources_model_dict = GenericComponentResponseResources.from_dict(generic_component_response_resources_model_json).__dict__
        generic_component_response_resources_model2 = GenericComponentResponseResources(**generic_component_response_resources_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_resources_model == generic_component_response_resources_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_resources_model_json2 = generic_component_response_resources_model.to_dict()
        assert generic_component_response_resources_model_json2 == generic_component_response_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericComponentResponseStorage
#-----------------------------------------------------------------------------
class TestGenericComponentResponseStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericComponentResponseStorage
    #--------------------------------------------------------
    def test_generic_component_response_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a GenericComponentResponseStorage model
        generic_component_response_storage_model_json = {}
        generic_component_response_storage_model_json['ca'] = storage_object_model
        generic_component_response_storage_model_json['peer'] = storage_object_model
        generic_component_response_storage_model_json['orderer'] = storage_object_model
        generic_component_response_storage_model_json['statedb'] = storage_object_model

        # Construct a model instance of GenericComponentResponseStorage by calling from_dict on the json representation
        generic_component_response_storage_model = GenericComponentResponseStorage.from_dict(generic_component_response_storage_model_json)
        assert generic_component_response_storage_model != False

        # Construct a model instance of GenericComponentResponseStorage by calling from_dict on the json representation
        generic_component_response_storage_model_dict = GenericComponentResponseStorage.from_dict(generic_component_response_storage_model_json).__dict__
        generic_component_response_storage_model2 = GenericComponentResponseStorage(**generic_component_response_storage_model_dict)

        # Verify the model instances are equivalent
        assert generic_component_response_storage_model == generic_component_response_storage_model2

        # Convert model instance back to dict and verify no loss of data
        generic_component_response_storage_model_json2 = generic_component_response_storage_model.to_dict()
        assert generic_component_response_storage_model_json2 == generic_component_response_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericResourceLimits
#-----------------------------------------------------------------------------
class TestGenericResourceLimits():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericResourceLimits
    #--------------------------------------------------------
    def test_generic_resource_limits_serialization(self):

        # Construct a json representation of a GenericResourceLimits model
        generic_resource_limits_model_json = {}
        generic_resource_limits_model_json['cpu'] = '8000m'
        generic_resource_limits_model_json['memory'] = '16384M'

        # Construct a model instance of GenericResourceLimits by calling from_dict on the json representation
        generic_resource_limits_model = GenericResourceLimits.from_dict(generic_resource_limits_model_json)
        assert generic_resource_limits_model != False

        # Construct a model instance of GenericResourceLimits by calling from_dict on the json representation
        generic_resource_limits_model_dict = GenericResourceLimits.from_dict(generic_resource_limits_model_json).__dict__
        generic_resource_limits_model2 = GenericResourceLimits(**generic_resource_limits_model_dict)

        # Verify the model instances are equivalent
        assert generic_resource_limits_model == generic_resource_limits_model2

        # Convert model instance back to dict and verify no loss of data
        generic_resource_limits_model_json2 = generic_resource_limits_model.to_dict()
        assert generic_resource_limits_model_json2 == generic_resource_limits_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericResources
#-----------------------------------------------------------------------------
class TestGenericResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericResources
    #--------------------------------------------------------
    def test_generic_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        # Construct a json representation of a GenericResources model
        generic_resources_model_json = {}
        generic_resources_model_json['requests'] = generic_resources_requests_model
        generic_resources_model_json['limits'] = generic_resource_limits_model

        # Construct a model instance of GenericResources by calling from_dict on the json representation
        generic_resources_model = GenericResources.from_dict(generic_resources_model_json)
        assert generic_resources_model != False

        # Construct a model instance of GenericResources by calling from_dict on the json representation
        generic_resources_model_dict = GenericResources.from_dict(generic_resources_model_json).__dict__
        generic_resources_model2 = GenericResources(**generic_resources_model_dict)

        # Verify the model instances are equivalent
        assert generic_resources_model == generic_resources_model2

        # Convert model instance back to dict and verify no loss of data
        generic_resources_model_json2 = generic_resources_model.to_dict()
        assert generic_resources_model_json2 == generic_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for GenericResourcesRequests
#-----------------------------------------------------------------------------
class TestGenericResourcesRequests():

    #--------------------------------------------------------
    # Test serialization/deserialization for GenericResourcesRequests
    #--------------------------------------------------------
    def test_generic_resources_requests_serialization(self):

        # Construct a json representation of a GenericResourcesRequests model
        generic_resources_requests_model_json = {}
        generic_resources_requests_model_json['cpu'] = '100m'
        generic_resources_requests_model_json['memory'] = '256M'

        # Construct a model instance of GenericResourcesRequests by calling from_dict on the json representation
        generic_resources_requests_model = GenericResourcesRequests.from_dict(generic_resources_requests_model_json)
        assert generic_resources_requests_model != False

        # Construct a model instance of GenericResourcesRequests by calling from_dict on the json representation
        generic_resources_requests_model_dict = GenericResourcesRequests.from_dict(generic_resources_requests_model_json).__dict__
        generic_resources_requests_model2 = GenericResourcesRequests(**generic_resources_requests_model_dict)

        # Verify the model instances are equivalent
        assert generic_resources_requests_model == generic_resources_requests_model2

        # Convert model instance back to dict and verify no loss of data
        generic_resources_requests_model_json2 = generic_resources_requests_model.to_dict()
        assert generic_resources_requests_model_json2 == generic_resources_requests_model_json

#-----------------------------------------------------------------------------
# Test Class for GetAthenaHealthStatsResponse
#-----------------------------------------------------------------------------
class TestGetAthenaHealthStatsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetAthenaHealthStatsResponse
    #--------------------------------------------------------
    def test_get_athena_health_stats_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        cpu_health_stats_times_model = {} # CpuHealthStatsTimes
        cpu_health_stats_times_model['idle'] = 131397203
        cpu_health_stats_times_model['irq'] = 6068640
        cpu_health_stats_times_model['nice'] = 0
        cpu_health_stats_times_model['sys'] = 9652328
        cpu_health_stats_times_model['user'] = 4152187

        cache_data_model = {} # CacheData
        cache_data_model['hits'] = 42
        cache_data_model['misses'] = 11
        cache_data_model['keys'] = 100
        cache_data_model['cache_size'] = '4.19 KiB'

        cpu_health_stats_model = {} # CpuHealthStats
        cpu_health_stats_model['model'] = 'Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz'
        cpu_health_stats_model['speed'] = 2592
        cpu_health_stats_model['times'] = cpu_health_stats_times_model

        get_athena_health_stats_response_optools_memory_usage_model = {} # GetAthenaHealthStatsResponseOPTOOLSMemoryUsage
        get_athena_health_stats_response_optools_memory_usage_model['rss'] = '56.1 MB'
        get_athena_health_stats_response_optools_memory_usage_model['heapTotal'] = '34.4 MB'
        get_athena_health_stats_response_optools_memory_usage_model['heapUsed'] = '28.4 MB'
        get_athena_health_stats_response_optools_memory_usage_model['external'] = '369.3 KB'

        get_athena_health_stats_response_optools_model = {} # GetAthenaHealthStatsResponseOPTOOLS
        get_athena_health_stats_response_optools_model['instance_id'] = 'p59ta'
        get_athena_health_stats_response_optools_model['now'] = 1542746836056
        get_athena_health_stats_response_optools_model['born'] = 1542746836056
        get_athena_health_stats_response_optools_model['up_time'] = '30 days'
        get_athena_health_stats_response_optools_model['memory_usage'] = get_athena_health_stats_response_optools_memory_usage_model
        get_athena_health_stats_response_optools_model['session_cache_stats'] = cache_data_model
        get_athena_health_stats_response_optools_model['couch_cache_stats'] = cache_data_model
        get_athena_health_stats_response_optools_model['iam_cache_stats'] = cache_data_model
        get_athena_health_stats_response_optools_model['proxy_cache'] = cache_data_model

        get_athena_health_stats_response_os_model = {} # GetAthenaHealthStatsResponseOS
        get_athena_health_stats_response_os_model['arch'] = 'x64'
        get_athena_health_stats_response_os_model['type'] = 'Windows_NT'
        get_athena_health_stats_response_os_model['endian'] = 'LE'
        get_athena_health_stats_response_os_model['loadavg'] = [0]
        get_athena_health_stats_response_os_model['cpus'] = [cpu_health_stats_model]
        get_athena_health_stats_response_os_model['total_memory'] = '31.7 GB'
        get_athena_health_stats_response_os_model['free_memory'] = '21.9 GB'
        get_athena_health_stats_response_os_model['up_time'] = '4.9 days'

        # Construct a json representation of a GetAthenaHealthStatsResponse model
        get_athena_health_stats_response_model_json = {}
        get_athena_health_stats_response_model_json['OPTOOLS'] = get_athena_health_stats_response_optools_model
        get_athena_health_stats_response_model_json['OS'] = get_athena_health_stats_response_os_model

        # Construct a model instance of GetAthenaHealthStatsResponse by calling from_dict on the json representation
        get_athena_health_stats_response_model = GetAthenaHealthStatsResponse.from_dict(get_athena_health_stats_response_model_json)
        assert get_athena_health_stats_response_model != False

        # Construct a model instance of GetAthenaHealthStatsResponse by calling from_dict on the json representation
        get_athena_health_stats_response_model_dict = GetAthenaHealthStatsResponse.from_dict(get_athena_health_stats_response_model_json).__dict__
        get_athena_health_stats_response_model2 = GetAthenaHealthStatsResponse(**get_athena_health_stats_response_model_dict)

        # Verify the model instances are equivalent
        assert get_athena_health_stats_response_model == get_athena_health_stats_response_model2

        # Convert model instance back to dict and verify no loss of data
        get_athena_health_stats_response_model_json2 = get_athena_health_stats_response_model.to_dict()
        assert get_athena_health_stats_response_model_json2 == get_athena_health_stats_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GetAthenaHealthStatsResponseOPTOOLS
#-----------------------------------------------------------------------------
class TestGetAthenaHealthStatsResponseOPTOOLS():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetAthenaHealthStatsResponseOPTOOLS
    #--------------------------------------------------------
    def test_get_athena_health_stats_response_optools_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        cache_data_model = {} # CacheData
        cache_data_model['hits'] = 42
        cache_data_model['misses'] = 11
        cache_data_model['keys'] = 100
        cache_data_model['cache_size'] = '4.19 KiB'

        get_athena_health_stats_response_optools_memory_usage_model = {} # GetAthenaHealthStatsResponseOPTOOLSMemoryUsage
        get_athena_health_stats_response_optools_memory_usage_model['rss'] = '56.1 MB'
        get_athena_health_stats_response_optools_memory_usage_model['heapTotal'] = '34.4 MB'
        get_athena_health_stats_response_optools_memory_usage_model['heapUsed'] = '28.4 MB'
        get_athena_health_stats_response_optools_memory_usage_model['external'] = '369.3 KB'

        # Construct a json representation of a GetAthenaHealthStatsResponseOPTOOLS model
        get_athena_health_stats_response_optools_model_json = {}
        get_athena_health_stats_response_optools_model_json['instance_id'] = 'p59ta'
        get_athena_health_stats_response_optools_model_json['now'] = 1542746836056
        get_athena_health_stats_response_optools_model_json['born'] = 1542746836056
        get_athena_health_stats_response_optools_model_json['up_time'] = '30 days'
        get_athena_health_stats_response_optools_model_json['memory_usage'] = get_athena_health_stats_response_optools_memory_usage_model
        get_athena_health_stats_response_optools_model_json['session_cache_stats'] = cache_data_model
        get_athena_health_stats_response_optools_model_json['couch_cache_stats'] = cache_data_model
        get_athena_health_stats_response_optools_model_json['iam_cache_stats'] = cache_data_model
        get_athena_health_stats_response_optools_model_json['proxy_cache'] = cache_data_model

        # Construct a model instance of GetAthenaHealthStatsResponseOPTOOLS by calling from_dict on the json representation
        get_athena_health_stats_response_optools_model = GetAthenaHealthStatsResponseOPTOOLS.from_dict(get_athena_health_stats_response_optools_model_json)
        assert get_athena_health_stats_response_optools_model != False

        # Construct a model instance of GetAthenaHealthStatsResponseOPTOOLS by calling from_dict on the json representation
        get_athena_health_stats_response_optools_model_dict = GetAthenaHealthStatsResponseOPTOOLS.from_dict(get_athena_health_stats_response_optools_model_json).__dict__
        get_athena_health_stats_response_optools_model2 = GetAthenaHealthStatsResponseOPTOOLS(**get_athena_health_stats_response_optools_model_dict)

        # Verify the model instances are equivalent
        assert get_athena_health_stats_response_optools_model == get_athena_health_stats_response_optools_model2

        # Convert model instance back to dict and verify no loss of data
        get_athena_health_stats_response_optools_model_json2 = get_athena_health_stats_response_optools_model.to_dict()
        assert get_athena_health_stats_response_optools_model_json2 == get_athena_health_stats_response_optools_model_json

#-----------------------------------------------------------------------------
# Test Class for GetAthenaHealthStatsResponseOPTOOLSMemoryUsage
#-----------------------------------------------------------------------------
class TestGetAthenaHealthStatsResponseOPTOOLSMemoryUsage():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetAthenaHealthStatsResponseOPTOOLSMemoryUsage
    #--------------------------------------------------------
    def test_get_athena_health_stats_response_optools_memory_usage_serialization(self):

        # Construct a json representation of a GetAthenaHealthStatsResponseOPTOOLSMemoryUsage model
        get_athena_health_stats_response_optools_memory_usage_model_json = {}
        get_athena_health_stats_response_optools_memory_usage_model_json['rss'] = '56.1 MB'
        get_athena_health_stats_response_optools_memory_usage_model_json['heapTotal'] = '34.4 MB'
        get_athena_health_stats_response_optools_memory_usage_model_json['heapUsed'] = '28.4 MB'
        get_athena_health_stats_response_optools_memory_usage_model_json['external'] = '369.3 KB'

        # Construct a model instance of GetAthenaHealthStatsResponseOPTOOLSMemoryUsage by calling from_dict on the json representation
        get_athena_health_stats_response_optools_memory_usage_model = GetAthenaHealthStatsResponseOPTOOLSMemoryUsage.from_dict(get_athena_health_stats_response_optools_memory_usage_model_json)
        assert get_athena_health_stats_response_optools_memory_usage_model != False

        # Construct a model instance of GetAthenaHealthStatsResponseOPTOOLSMemoryUsage by calling from_dict on the json representation
        get_athena_health_stats_response_optools_memory_usage_model_dict = GetAthenaHealthStatsResponseOPTOOLSMemoryUsage.from_dict(get_athena_health_stats_response_optools_memory_usage_model_json).__dict__
        get_athena_health_stats_response_optools_memory_usage_model2 = GetAthenaHealthStatsResponseOPTOOLSMemoryUsage(**get_athena_health_stats_response_optools_memory_usage_model_dict)

        # Verify the model instances are equivalent
        assert get_athena_health_stats_response_optools_memory_usage_model == get_athena_health_stats_response_optools_memory_usage_model2

        # Convert model instance back to dict and verify no loss of data
        get_athena_health_stats_response_optools_memory_usage_model_json2 = get_athena_health_stats_response_optools_memory_usage_model.to_dict()
        assert get_athena_health_stats_response_optools_memory_usage_model_json2 == get_athena_health_stats_response_optools_memory_usage_model_json

#-----------------------------------------------------------------------------
# Test Class for GetAthenaHealthStatsResponseOS
#-----------------------------------------------------------------------------
class TestGetAthenaHealthStatsResponseOS():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetAthenaHealthStatsResponseOS
    #--------------------------------------------------------
    def test_get_athena_health_stats_response_os_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        cpu_health_stats_times_model = {} # CpuHealthStatsTimes
        cpu_health_stats_times_model['idle'] = 131397203
        cpu_health_stats_times_model['irq'] = 6068640
        cpu_health_stats_times_model['nice'] = 0
        cpu_health_stats_times_model['sys'] = 9652328
        cpu_health_stats_times_model['user'] = 4152187

        cpu_health_stats_model = {} # CpuHealthStats
        cpu_health_stats_model['model'] = 'Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz'
        cpu_health_stats_model['speed'] = 2592
        cpu_health_stats_model['times'] = cpu_health_stats_times_model

        # Construct a json representation of a GetAthenaHealthStatsResponseOS model
        get_athena_health_stats_response_os_model_json = {}
        get_athena_health_stats_response_os_model_json['arch'] = 'x64'
        get_athena_health_stats_response_os_model_json['type'] = 'Windows_NT'
        get_athena_health_stats_response_os_model_json['endian'] = 'LE'
        get_athena_health_stats_response_os_model_json['loadavg'] = [0]
        get_athena_health_stats_response_os_model_json['cpus'] = [cpu_health_stats_model]
        get_athena_health_stats_response_os_model_json['total_memory'] = '31.7 GB'
        get_athena_health_stats_response_os_model_json['free_memory'] = '21.9 GB'
        get_athena_health_stats_response_os_model_json['up_time'] = '4.9 days'

        # Construct a model instance of GetAthenaHealthStatsResponseOS by calling from_dict on the json representation
        get_athena_health_stats_response_os_model = GetAthenaHealthStatsResponseOS.from_dict(get_athena_health_stats_response_os_model_json)
        assert get_athena_health_stats_response_os_model != False

        # Construct a model instance of GetAthenaHealthStatsResponseOS by calling from_dict on the json representation
        get_athena_health_stats_response_os_model_dict = GetAthenaHealthStatsResponseOS.from_dict(get_athena_health_stats_response_os_model_json).__dict__
        get_athena_health_stats_response_os_model2 = GetAthenaHealthStatsResponseOS(**get_athena_health_stats_response_os_model_dict)

        # Verify the model instances are equivalent
        assert get_athena_health_stats_response_os_model == get_athena_health_stats_response_os_model2

        # Convert model instance back to dict and verify no loss of data
        get_athena_health_stats_response_os_model_json2 = get_athena_health_stats_response_os_model.to_dict()
        assert get_athena_health_stats_response_os_model_json2 == get_athena_health_stats_response_os_model_json

#-----------------------------------------------------------------------------
# Test Class for GetFabricVersionsResponse
#-----------------------------------------------------------------------------
class TestGetFabricVersionsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetFabricVersionsResponse
    #--------------------------------------------------------
    def test_get_fabric_versions_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        fab_version_object_model = {} # FabVersionObject
        fab_version_object_model['default'] = True
        fab_version_object_model['version'] = '1.4.6-2'
        fab_version_object_model['image'] = { 'foo': 'bar' }

        fabric_version_dictionary_model = {} # FabricVersionDictionary
        fabric_version_dictionary_model['1.4.6-2'] = fab_version_object_model
        fabric_version_dictionary_model['2.1.0-0'] = fab_version_object_model
        fabric_version_dictionary_model['foo'] = { 'foo': 'bar' }

        get_fabric_versions_response_versions_model = {} # GetFabricVersionsResponseVersions
        get_fabric_versions_response_versions_model['ca'] = fabric_version_dictionary_model
        get_fabric_versions_response_versions_model['peer'] = fabric_version_dictionary_model
        get_fabric_versions_response_versions_model['orderer'] = fabric_version_dictionary_model

        # Construct a json representation of a GetFabricVersionsResponse model
        get_fabric_versions_response_model_json = {}
        get_fabric_versions_response_model_json['versions'] = get_fabric_versions_response_versions_model

        # Construct a model instance of GetFabricVersionsResponse by calling from_dict on the json representation
        get_fabric_versions_response_model = GetFabricVersionsResponse.from_dict(get_fabric_versions_response_model_json)
        assert get_fabric_versions_response_model != False

        # Construct a model instance of GetFabricVersionsResponse by calling from_dict on the json representation
        get_fabric_versions_response_model_dict = GetFabricVersionsResponse.from_dict(get_fabric_versions_response_model_json).__dict__
        get_fabric_versions_response_model2 = GetFabricVersionsResponse(**get_fabric_versions_response_model_dict)

        # Verify the model instances are equivalent
        assert get_fabric_versions_response_model == get_fabric_versions_response_model2

        # Convert model instance back to dict and verify no loss of data
        get_fabric_versions_response_model_json2 = get_fabric_versions_response_model.to_dict()
        assert get_fabric_versions_response_model_json2 == get_fabric_versions_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GetFabricVersionsResponseVersions
#-----------------------------------------------------------------------------
class TestGetFabricVersionsResponseVersions():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetFabricVersionsResponseVersions
    #--------------------------------------------------------
    def test_get_fabric_versions_response_versions_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        fab_version_object_model = {} # FabVersionObject
        fab_version_object_model['default'] = True
        fab_version_object_model['version'] = '1.4.6-2'
        fab_version_object_model['image'] = { 'foo': 'bar' }

        fabric_version_dictionary_model = {} # FabricVersionDictionary
        fabric_version_dictionary_model['1.4.6-2'] = fab_version_object_model
        fabric_version_dictionary_model['2.1.0-0'] = fab_version_object_model
        fabric_version_dictionary_model['foo'] = { 'foo': 'bar' }

        # Construct a json representation of a GetFabricVersionsResponseVersions model
        get_fabric_versions_response_versions_model_json = {}
        get_fabric_versions_response_versions_model_json['ca'] = fabric_version_dictionary_model
        get_fabric_versions_response_versions_model_json['peer'] = fabric_version_dictionary_model
        get_fabric_versions_response_versions_model_json['orderer'] = fabric_version_dictionary_model

        # Construct a model instance of GetFabricVersionsResponseVersions by calling from_dict on the json representation
        get_fabric_versions_response_versions_model = GetFabricVersionsResponseVersions.from_dict(get_fabric_versions_response_versions_model_json)
        assert get_fabric_versions_response_versions_model != False

        # Construct a model instance of GetFabricVersionsResponseVersions by calling from_dict on the json representation
        get_fabric_versions_response_versions_model_dict = GetFabricVersionsResponseVersions.from_dict(get_fabric_versions_response_versions_model_json).__dict__
        get_fabric_versions_response_versions_model2 = GetFabricVersionsResponseVersions(**get_fabric_versions_response_versions_model_dict)

        # Verify the model instances are equivalent
        assert get_fabric_versions_response_versions_model == get_fabric_versions_response_versions_model2

        # Convert model instance back to dict and verify no loss of data
        get_fabric_versions_response_versions_model_json2 = get_fabric_versions_response_versions_model.to_dict()
        assert get_fabric_versions_response_versions_model_json2 == get_fabric_versions_response_versions_model_json

#-----------------------------------------------------------------------------
# Test Class for GetMSPCertificateResponse
#-----------------------------------------------------------------------------
class TestGetMSPCertificateResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetMSPCertificateResponse
    #--------------------------------------------------------
    def test_get_msp_certificate_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        msp_public_data_model = {} # MspPublicData
        msp_public_data_model['msp_id'] = 'Org1'
        msp_public_data_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_public_data_model['admins'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_public_data_model['tls_root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a json representation of a GetMSPCertificateResponse model
        get_msp_certificate_response_model_json = {}
        get_msp_certificate_response_model_json['msps'] = [msp_public_data_model]

        # Construct a model instance of GetMSPCertificateResponse by calling from_dict on the json representation
        get_msp_certificate_response_model = GetMSPCertificateResponse.from_dict(get_msp_certificate_response_model_json)
        assert get_msp_certificate_response_model != False

        # Construct a model instance of GetMSPCertificateResponse by calling from_dict on the json representation
        get_msp_certificate_response_model_dict = GetMSPCertificateResponse.from_dict(get_msp_certificate_response_model_json).__dict__
        get_msp_certificate_response_model2 = GetMSPCertificateResponse(**get_msp_certificate_response_model_dict)

        # Verify the model instances are equivalent
        assert get_msp_certificate_response_model == get_msp_certificate_response_model2

        # Convert model instance back to dict and verify no loss of data
        get_msp_certificate_response_model_json2 = get_msp_certificate_response_model.to_dict()
        assert get_msp_certificate_response_model_json2 == get_msp_certificate_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GetMultiComponentsResponse
#-----------------------------------------------------------------------------
class TestGetMultiComponentsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetMultiComponentsResponse
    #--------------------------------------------------------
    def test_get_multi_components_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_component_response_msp_ca_model = {} # GenericComponentResponseMspCa
        generic_component_response_msp_ca_model['name'] = 'org1CA'
        generic_component_response_msp_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_component_response_msp_component_model = {} # GenericComponentResponseMspComponent
        generic_component_response_msp_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        generic_component_response_msp_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_component_response_msp_tlsca_model = {} # GenericComponentResponseMspTlsca
        generic_component_response_msp_tlsca_model['name'] = 'org1tlsCA'
        generic_component_response_msp_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        generic_component_response_msp_model = {} # GenericComponentResponseMsp
        generic_component_response_msp_model['ca'] = generic_component_response_msp_ca_model
        generic_component_response_msp_model['tlsca'] = generic_component_response_msp_tlsca_model
        generic_component_response_msp_model['component'] = generic_component_response_msp_component_model

        generic_component_response_resources_model = {} # GenericComponentResponseResources
        generic_component_response_resources_model['ca'] = generic_resources_model
        generic_component_response_resources_model['peer'] = generic_resources_model
        generic_component_response_resources_model['orderer'] = generic_resources_model
        generic_component_response_resources_model['proxy'] = generic_resources_model
        generic_component_response_resources_model['statedb'] = generic_resources_model

        generic_component_response_storage_model = {} # GenericComponentResponseStorage
        generic_component_response_storage_model['ca'] = storage_object_model
        generic_component_response_storage_model['peer'] = storage_object_model
        generic_component_response_storage_model['orderer'] = storage_object_model
        generic_component_response_storage_model['statedb'] = storage_object_model

        node_ou_general_model = {} # NodeOuGeneral
        node_ou_general_model['enabled'] = True

        generic_component_response_model = {} # GenericComponentResponse
        generic_component_response_model['id'] = 'myca-2'
        generic_component_response_model['type'] = 'fabric-ca'
        generic_component_response_model['display_name'] = 'Example CA'
        generic_component_response_model['grpcwp_url'] = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        generic_component_response_model['api_url'] = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        generic_component_response_model['operations_url'] = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        generic_component_response_model['msp'] = generic_component_response_msp_model
        generic_component_response_model['msp_id'] = 'Org1'
        generic_component_response_model['location'] = 'ibmcloud'
        generic_component_response_model['node_ou'] = node_ou_general_model
        generic_component_response_model['resources'] = generic_component_response_resources_model
        generic_component_response_model['scheme_version'] = 'v1'
        generic_component_response_model['state_db'] = 'couchdb'
        generic_component_response_model['storage'] = generic_component_response_storage_model
        generic_component_response_model['timestamp'] = 1537262855753
        generic_component_response_model['tags'] = ['fabric-ca']
        generic_component_response_model['version'] = '1.4.6-1'
        generic_component_response_model['zone'] = '-'

        # Construct a json representation of a GetMultiComponentsResponse model
        get_multi_components_response_model_json = {}
        get_multi_components_response_model_json['components'] = [generic_component_response_model]

        # Construct a model instance of GetMultiComponentsResponse by calling from_dict on the json representation
        get_multi_components_response_model = GetMultiComponentsResponse.from_dict(get_multi_components_response_model_json)
        assert get_multi_components_response_model != False

        # Construct a model instance of GetMultiComponentsResponse by calling from_dict on the json representation
        get_multi_components_response_model_dict = GetMultiComponentsResponse.from_dict(get_multi_components_response_model_json).__dict__
        get_multi_components_response_model2 = GetMultiComponentsResponse(**get_multi_components_response_model_dict)

        # Verify the model instances are equivalent
        assert get_multi_components_response_model == get_multi_components_response_model2

        # Convert model instance back to dict and verify no loss of data
        get_multi_components_response_model_json2 = get_multi_components_response_model.to_dict()
        assert get_multi_components_response_model_json2 == get_multi_components_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GetNotificationsResponse
#-----------------------------------------------------------------------------
class TestGetNotificationsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetNotificationsResponse
    #--------------------------------------------------------
    def test_get_notifications_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        notification_data_model = {} # NotificationData
        notification_data_model['id'] = '60d84819bfa17adb4174ff3a1c52b5d6'
        notification_data_model['type'] = 'notification'
        notification_data_model['status'] = 'pending'
        notification_data_model['by'] = 'd******a@us.ibm.com'
        notification_data_model['message'] = 'Restarting application'
        notification_data_model['ts_display'] = 1537262855753

        # Construct a json representation of a GetNotificationsResponse model
        get_notifications_response_model_json = {}
        get_notifications_response_model_json['total'] = 10
        get_notifications_response_model_json['returning'] = 3
        get_notifications_response_model_json['notifications'] = [notification_data_model]

        # Construct a model instance of GetNotificationsResponse by calling from_dict on the json representation
        get_notifications_response_model = GetNotificationsResponse.from_dict(get_notifications_response_model_json)
        assert get_notifications_response_model != False

        # Construct a model instance of GetNotificationsResponse by calling from_dict on the json representation
        get_notifications_response_model_dict = GetNotificationsResponse.from_dict(get_notifications_response_model_json).__dict__
        get_notifications_response_model2 = GetNotificationsResponse(**get_notifications_response_model_dict)

        # Verify the model instances are equivalent
        assert get_notifications_response_model == get_notifications_response_model2

        # Convert model instance back to dict and verify no loss of data
        get_notifications_response_model_json2 = get_notifications_response_model.to_dict()
        assert get_notifications_response_model_json2 == get_notifications_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponse
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponse
    #--------------------------------------------------------
    def test_get_public_settings_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        logging_settings_client_model = {} # LoggingSettingsClient
        logging_settings_client_model['enabled'] = True
        logging_settings_client_model['level'] = 'silly'
        logging_settings_client_model['unique_name'] = False

        logging_settings_server_model = {} # LoggingSettingsServer
        logging_settings_server_model['enabled'] = True
        logging_settings_server_model['level'] = 'silly'
        logging_settings_server_model['unique_name'] = False

        log_settings_response_model = {} # LogSettingsResponse
        log_settings_response_model['client'] = logging_settings_client_model
        log_settings_response_model['server'] = logging_settings_server_model

        get_public_settings_response_clusterdata_model = {} # GetPublicSettingsResponseCLUSTERDATA
        get_public_settings_response_clusterdata_model['type'] = 'paid'

        get_public_settings_response_crn_model = {} # GetPublicSettingsResponseCRN
        get_public_settings_response_crn_model['account_id'] = 'a/abcd'
        get_public_settings_response_crn_model['c_name'] = 'staging'
        get_public_settings_response_crn_model['c_type'] = 'public'
        get_public_settings_response_crn_model['instance_id'] = 'abc123'
        get_public_settings_response_crn_model['location'] = 'us-south'
        get_public_settings_response_crn_model['resource_id'] = '-'
        get_public_settings_response_crn_model['resource_type'] = '-'
        get_public_settings_response_crn_model['service_name'] = 'blockchain'
        get_public_settings_response_crn_model['version'] = 'v1'

        get_public_settings_response_fabriccapabilities_model = {} # GetPublicSettingsResponseFABRICCAPABILITIES
        get_public_settings_response_fabriccapabilities_model['application'] = ['V1_1']
        get_public_settings_response_fabriccapabilities_model['channel'] = ['V1_1']
        get_public_settings_response_fabriccapabilities_model['orderer'] = ['V1_1']

        get_public_settings_response_filelogging_model = {} # GetPublicSettingsResponseFILELOGGING
        get_public_settings_response_filelogging_model['server'] = log_settings_response_model
        get_public_settings_response_filelogging_model['client'] = log_settings_response_model

        get_public_settings_response_inactivitytimeouts_model = {} # GetPublicSettingsResponseINACTIVITYTIMEOUTS
        get_public_settings_response_inactivitytimeouts_model['enabled'] = True
        get_public_settings_response_inactivitytimeouts_model['max_idle_time'] = 60000

        get_public_settings_response_versions_model = {} # GetPublicSettingsResponseVERSIONS
        get_public_settings_response_versions_model['apollo'] = '65f3cbfd'
        get_public_settings_response_versions_model['athena'] = '1198f94'
        get_public_settings_response_versions_model['stitch'] = '0f1a0c6'
        get_public_settings_response_versions_model['tag'] = 'v0.4.31'

        settings_timestamp_data_model = {} # SettingsTimestampData
        settings_timestamp_data_model['now'] = 1542746836056
        settings_timestamp_data_model['born'] = 1542746836056
        settings_timestamp_data_model['next_settings_update'] = '1.2 mins'
        settings_timestamp_data_model['up_time'] = '30 days'

        # Construct a json representation of a GetPublicSettingsResponse model
        get_public_settings_response_model_json = {}
        get_public_settings_response_model_json['ACTIVITY_TRACKER_PATH'] = '/logs'
        get_public_settings_response_model_json['ATHENA_ID'] = '17v7e'
        get_public_settings_response_model_json['AUTH_SCHEME'] = 'iam'
        get_public_settings_response_model_json['CALLBACK_URI'] = '/auth/cb'
        get_public_settings_response_model_json['CLUSTER_DATA'] = get_public_settings_response_clusterdata_model
        get_public_settings_response_model_json['CONFIGTXLATOR_URL'] = 'https://n3a3ec3-configtxlator.ibp.us-south.containers.appdomain.cloud'
        get_public_settings_response_model_json['CRN'] = get_public_settings_response_crn_model
        get_public_settings_response_model_json['CRN_STRING'] = 'crn:v1:staging:public:blockchain:us-south:a/abcd:abc123::'
        get_public_settings_response_model_json['CSP_HEADER_VALUES'] = ['-']
        get_public_settings_response_model_json['DB_SYSTEM'] = 'system'
        get_public_settings_response_model_json['DEPLOYER_URL'] = 'https://api.dev.blockchain.cloud.ibm.com'
        get_public_settings_response_model_json['DOMAIN'] = 'localhost'
        get_public_settings_response_model_json['ENVIRONMENT'] = 'prod'
        get_public_settings_response_model_json['FABRIC_CAPABILITIES'] = get_public_settings_response_fabriccapabilities_model
        get_public_settings_response_model_json['FEATURE_FLAGS'] = { 'foo': 'bar' }
        get_public_settings_response_model_json['FILE_LOGGING'] = get_public_settings_response_filelogging_model
        get_public_settings_response_model_json['HOST_URL'] = 'http://localhost:3000'
        get_public_settings_response_model_json['IAM_CACHE_ENABLED'] = True
        get_public_settings_response_model_json['IAM_URL'] = '-'
        get_public_settings_response_model_json['IBM_ID_CALLBACK_URL'] = 'http://localhost:3000/auth/login'
        get_public_settings_response_model_json['IGNORE_CONFIG_FILE'] = True
        get_public_settings_response_model_json['INACTIVITY_TIMEOUTS'] = get_public_settings_response_inactivitytimeouts_model
        get_public_settings_response_model_json['INFRASTRUCTURE'] = 'ibmcloud'
        get_public_settings_response_model_json['LANDING_URL'] = 'http://localhost:3000'
        get_public_settings_response_model_json['LOGIN_URI'] = '/auth/login'
        get_public_settings_response_model_json['LOGOUT_URI'] = '/auth/logout'
        get_public_settings_response_model_json['MAX_REQ_PER_MIN'] = 25
        get_public_settings_response_model_json['MAX_REQ_PER_MIN_AK'] = 25
        get_public_settings_response_model_json['MEMORY_CACHE_ENABLED'] = True
        get_public_settings_response_model_json['PORT'] = '3000'
        get_public_settings_response_model_json['PROXY_CACHE_ENABLED'] = True
        get_public_settings_response_model_json['PROXY_TLS_FABRIC_REQS'] = 'always'
        get_public_settings_response_model_json['PROXY_TLS_HTTP_URL'] = 'http://localhost:3000'
        get_public_settings_response_model_json['PROXY_TLS_WS_URL'] = { 'foo': 'bar' }
        get_public_settings_response_model_json['REGION'] = 'us_south'
        get_public_settings_response_model_json['SESSION_CACHE_ENABLED'] = True
        get_public_settings_response_model_json['TIMEOUTS'] = { 'foo': 'bar' }
        get_public_settings_response_model_json['TIMESTAMPS'] = settings_timestamp_data_model
        get_public_settings_response_model_json['TRANSACTION_VISIBILITY'] = { 'foo': 'bar' }
        get_public_settings_response_model_json['TRUST_PROXY'] = 'loopback'
        get_public_settings_response_model_json['TRUST_UNKNOWN_CERTS'] = True
        get_public_settings_response_model_json['VERSIONS'] = get_public_settings_response_versions_model

        # Construct a model instance of GetPublicSettingsResponse by calling from_dict on the json representation
        get_public_settings_response_model = GetPublicSettingsResponse.from_dict(get_public_settings_response_model_json)
        assert get_public_settings_response_model != False

        # Construct a model instance of GetPublicSettingsResponse by calling from_dict on the json representation
        get_public_settings_response_model_dict = GetPublicSettingsResponse.from_dict(get_public_settings_response_model_json).__dict__
        get_public_settings_response_model2 = GetPublicSettingsResponse(**get_public_settings_response_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_model == get_public_settings_response_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_model_json2 = get_public_settings_response_model.to_dict()
        assert get_public_settings_response_model_json2 == get_public_settings_response_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponseCLUSTERDATA
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponseCLUSTERDATA():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponseCLUSTERDATA
    #--------------------------------------------------------
    def test_get_public_settings_response_clusterdata_serialization(self):

        # Construct a json representation of a GetPublicSettingsResponseCLUSTERDATA model
        get_public_settings_response_clusterdata_model_json = {}
        get_public_settings_response_clusterdata_model_json['type'] = 'paid'

        # Construct a model instance of GetPublicSettingsResponseCLUSTERDATA by calling from_dict on the json representation
        get_public_settings_response_clusterdata_model = GetPublicSettingsResponseCLUSTERDATA.from_dict(get_public_settings_response_clusterdata_model_json)
        assert get_public_settings_response_clusterdata_model != False

        # Construct a model instance of GetPublicSettingsResponseCLUSTERDATA by calling from_dict on the json representation
        get_public_settings_response_clusterdata_model_dict = GetPublicSettingsResponseCLUSTERDATA.from_dict(get_public_settings_response_clusterdata_model_json).__dict__
        get_public_settings_response_clusterdata_model2 = GetPublicSettingsResponseCLUSTERDATA(**get_public_settings_response_clusterdata_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_clusterdata_model == get_public_settings_response_clusterdata_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_clusterdata_model_json2 = get_public_settings_response_clusterdata_model.to_dict()
        assert get_public_settings_response_clusterdata_model_json2 == get_public_settings_response_clusterdata_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponseCRN
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponseCRN():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponseCRN
    #--------------------------------------------------------
    def test_get_public_settings_response_crn_serialization(self):

        # Construct a json representation of a GetPublicSettingsResponseCRN model
        get_public_settings_response_crn_model_json = {}
        get_public_settings_response_crn_model_json['account_id'] = 'a/abcd'
        get_public_settings_response_crn_model_json['c_name'] = 'staging'
        get_public_settings_response_crn_model_json['c_type'] = 'public'
        get_public_settings_response_crn_model_json['instance_id'] = 'abc123'
        get_public_settings_response_crn_model_json['location'] = 'us-south'
        get_public_settings_response_crn_model_json['resource_id'] = '-'
        get_public_settings_response_crn_model_json['resource_type'] = '-'
        get_public_settings_response_crn_model_json['service_name'] = 'blockchain'
        get_public_settings_response_crn_model_json['version'] = 'v1'

        # Construct a model instance of GetPublicSettingsResponseCRN by calling from_dict on the json representation
        get_public_settings_response_crn_model = GetPublicSettingsResponseCRN.from_dict(get_public_settings_response_crn_model_json)
        assert get_public_settings_response_crn_model != False

        # Construct a model instance of GetPublicSettingsResponseCRN by calling from_dict on the json representation
        get_public_settings_response_crn_model_dict = GetPublicSettingsResponseCRN.from_dict(get_public_settings_response_crn_model_json).__dict__
        get_public_settings_response_crn_model2 = GetPublicSettingsResponseCRN(**get_public_settings_response_crn_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_crn_model == get_public_settings_response_crn_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_crn_model_json2 = get_public_settings_response_crn_model.to_dict()
        assert get_public_settings_response_crn_model_json2 == get_public_settings_response_crn_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponseFABRICCAPABILITIES
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponseFABRICCAPABILITIES():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponseFABRICCAPABILITIES
    #--------------------------------------------------------
    def test_get_public_settings_response_fabriccapabilities_serialization(self):

        # Construct a json representation of a GetPublicSettingsResponseFABRICCAPABILITIES model
        get_public_settings_response_fabriccapabilities_model_json = {}
        get_public_settings_response_fabriccapabilities_model_json['application'] = ['V1_1']
        get_public_settings_response_fabriccapabilities_model_json['channel'] = ['V1_1']
        get_public_settings_response_fabriccapabilities_model_json['orderer'] = ['V1_1']

        # Construct a model instance of GetPublicSettingsResponseFABRICCAPABILITIES by calling from_dict on the json representation
        get_public_settings_response_fabriccapabilities_model = GetPublicSettingsResponseFABRICCAPABILITIES.from_dict(get_public_settings_response_fabriccapabilities_model_json)
        assert get_public_settings_response_fabriccapabilities_model != False

        # Construct a model instance of GetPublicSettingsResponseFABRICCAPABILITIES by calling from_dict on the json representation
        get_public_settings_response_fabriccapabilities_model_dict = GetPublicSettingsResponseFABRICCAPABILITIES.from_dict(get_public_settings_response_fabriccapabilities_model_json).__dict__
        get_public_settings_response_fabriccapabilities_model2 = GetPublicSettingsResponseFABRICCAPABILITIES(**get_public_settings_response_fabriccapabilities_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_fabriccapabilities_model == get_public_settings_response_fabriccapabilities_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_fabriccapabilities_model_json2 = get_public_settings_response_fabriccapabilities_model.to_dict()
        assert get_public_settings_response_fabriccapabilities_model_json2 == get_public_settings_response_fabriccapabilities_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponseFILELOGGING
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponseFILELOGGING():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponseFILELOGGING
    #--------------------------------------------------------
    def test_get_public_settings_response_filelogging_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        logging_settings_client_model = {} # LoggingSettingsClient
        logging_settings_client_model['enabled'] = True
        logging_settings_client_model['level'] = 'silly'
        logging_settings_client_model['unique_name'] = False

        logging_settings_server_model = {} # LoggingSettingsServer
        logging_settings_server_model['enabled'] = True
        logging_settings_server_model['level'] = 'silly'
        logging_settings_server_model['unique_name'] = False

        log_settings_response_model = {} # LogSettingsResponse
        log_settings_response_model['client'] = logging_settings_client_model
        log_settings_response_model['server'] = logging_settings_server_model

        # Construct a json representation of a GetPublicSettingsResponseFILELOGGING model
        get_public_settings_response_filelogging_model_json = {}
        get_public_settings_response_filelogging_model_json['server'] = log_settings_response_model
        get_public_settings_response_filelogging_model_json['client'] = log_settings_response_model

        # Construct a model instance of GetPublicSettingsResponseFILELOGGING by calling from_dict on the json representation
        get_public_settings_response_filelogging_model = GetPublicSettingsResponseFILELOGGING.from_dict(get_public_settings_response_filelogging_model_json)
        assert get_public_settings_response_filelogging_model != False

        # Construct a model instance of GetPublicSettingsResponseFILELOGGING by calling from_dict on the json representation
        get_public_settings_response_filelogging_model_dict = GetPublicSettingsResponseFILELOGGING.from_dict(get_public_settings_response_filelogging_model_json).__dict__
        get_public_settings_response_filelogging_model2 = GetPublicSettingsResponseFILELOGGING(**get_public_settings_response_filelogging_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_filelogging_model == get_public_settings_response_filelogging_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_filelogging_model_json2 = get_public_settings_response_filelogging_model.to_dict()
        assert get_public_settings_response_filelogging_model_json2 == get_public_settings_response_filelogging_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponseINACTIVITYTIMEOUTS
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponseINACTIVITYTIMEOUTS():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponseINACTIVITYTIMEOUTS
    #--------------------------------------------------------
    def test_get_public_settings_response_inactivitytimeouts_serialization(self):

        # Construct a json representation of a GetPublicSettingsResponseINACTIVITYTIMEOUTS model
        get_public_settings_response_inactivitytimeouts_model_json = {}
        get_public_settings_response_inactivitytimeouts_model_json['enabled'] = True
        get_public_settings_response_inactivitytimeouts_model_json['max_idle_time'] = 60000

        # Construct a model instance of GetPublicSettingsResponseINACTIVITYTIMEOUTS by calling from_dict on the json representation
        get_public_settings_response_inactivitytimeouts_model = GetPublicSettingsResponseINACTIVITYTIMEOUTS.from_dict(get_public_settings_response_inactivitytimeouts_model_json)
        assert get_public_settings_response_inactivitytimeouts_model != False

        # Construct a model instance of GetPublicSettingsResponseINACTIVITYTIMEOUTS by calling from_dict on the json representation
        get_public_settings_response_inactivitytimeouts_model_dict = GetPublicSettingsResponseINACTIVITYTIMEOUTS.from_dict(get_public_settings_response_inactivitytimeouts_model_json).__dict__
        get_public_settings_response_inactivitytimeouts_model2 = GetPublicSettingsResponseINACTIVITYTIMEOUTS(**get_public_settings_response_inactivitytimeouts_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_inactivitytimeouts_model == get_public_settings_response_inactivitytimeouts_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_inactivitytimeouts_model_json2 = get_public_settings_response_inactivitytimeouts_model.to_dict()
        assert get_public_settings_response_inactivitytimeouts_model_json2 == get_public_settings_response_inactivitytimeouts_model_json

#-----------------------------------------------------------------------------
# Test Class for GetPublicSettingsResponseVERSIONS
#-----------------------------------------------------------------------------
class TestGetPublicSettingsResponseVERSIONS():

    #--------------------------------------------------------
    # Test serialization/deserialization for GetPublicSettingsResponseVERSIONS
    #--------------------------------------------------------
    def test_get_public_settings_response_versions_serialization(self):

        # Construct a json representation of a GetPublicSettingsResponseVERSIONS model
        get_public_settings_response_versions_model_json = {}
        get_public_settings_response_versions_model_json['apollo'] = '65f3cbfd'
        get_public_settings_response_versions_model_json['athena'] = '1198f94'
        get_public_settings_response_versions_model_json['stitch'] = '0f1a0c6'
        get_public_settings_response_versions_model_json['tag'] = 'v0.4.31'

        # Construct a model instance of GetPublicSettingsResponseVERSIONS by calling from_dict on the json representation
        get_public_settings_response_versions_model = GetPublicSettingsResponseVERSIONS.from_dict(get_public_settings_response_versions_model_json)
        assert get_public_settings_response_versions_model != False

        # Construct a model instance of GetPublicSettingsResponseVERSIONS by calling from_dict on the json representation
        get_public_settings_response_versions_model_dict = GetPublicSettingsResponseVERSIONS.from_dict(get_public_settings_response_versions_model_json).__dict__
        get_public_settings_response_versions_model2 = GetPublicSettingsResponseVERSIONS(**get_public_settings_response_versions_model_dict)

        # Verify the model instances are equivalent
        assert get_public_settings_response_versions_model == get_public_settings_response_versions_model2

        # Convert model instance back to dict and verify no loss of data
        get_public_settings_response_versions_model_json2 = get_public_settings_response_versions_model.to_dict()
        assert get_public_settings_response_versions_model_json2 == get_public_settings_response_versions_model_json

#-----------------------------------------------------------------------------
# Test Class for ImportCaBodyMsp
#-----------------------------------------------------------------------------
class TestImportCaBodyMsp():

    #--------------------------------------------------------
    # Test serialization/deserialization for ImportCaBodyMsp
    #--------------------------------------------------------
    def test_import_ca_body_msp_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        import_ca_body_msp_ca_model = {} # ImportCaBodyMspCa
        import_ca_body_msp_ca_model['name'] = 'org1CA'
        import_ca_body_msp_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        import_ca_body_msp_component_model = {} # ImportCaBodyMspComponent
        import_ca_body_msp_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='

        import_ca_body_msp_tlsca_model = {} # ImportCaBodyMspTlsca
        import_ca_body_msp_tlsca_model['name'] = 'org1tlsCA'
        import_ca_body_msp_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a json representation of a ImportCaBodyMsp model
        import_ca_body_msp_model_json = {}
        import_ca_body_msp_model_json['ca'] = import_ca_body_msp_ca_model
        import_ca_body_msp_model_json['tlsca'] = import_ca_body_msp_tlsca_model
        import_ca_body_msp_model_json['component'] = import_ca_body_msp_component_model

        # Construct a model instance of ImportCaBodyMsp by calling from_dict on the json representation
        import_ca_body_msp_model = ImportCaBodyMsp.from_dict(import_ca_body_msp_model_json)
        assert import_ca_body_msp_model != False

        # Construct a model instance of ImportCaBodyMsp by calling from_dict on the json representation
        import_ca_body_msp_model_dict = ImportCaBodyMsp.from_dict(import_ca_body_msp_model_json).__dict__
        import_ca_body_msp_model2 = ImportCaBodyMsp(**import_ca_body_msp_model_dict)

        # Verify the model instances are equivalent
        assert import_ca_body_msp_model == import_ca_body_msp_model2

        # Convert model instance back to dict and verify no loss of data
        import_ca_body_msp_model_json2 = import_ca_body_msp_model.to_dict()
        assert import_ca_body_msp_model_json2 == import_ca_body_msp_model_json

#-----------------------------------------------------------------------------
# Test Class for ImportCaBodyMspCa
#-----------------------------------------------------------------------------
class TestImportCaBodyMspCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for ImportCaBodyMspCa
    #--------------------------------------------------------
    def test_import_ca_body_msp_ca_serialization(self):

        # Construct a json representation of a ImportCaBodyMspCa model
        import_ca_body_msp_ca_model_json = {}
        import_ca_body_msp_ca_model_json['name'] = 'org1CA'
        import_ca_body_msp_ca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of ImportCaBodyMspCa by calling from_dict on the json representation
        import_ca_body_msp_ca_model = ImportCaBodyMspCa.from_dict(import_ca_body_msp_ca_model_json)
        assert import_ca_body_msp_ca_model != False

        # Construct a model instance of ImportCaBodyMspCa by calling from_dict on the json representation
        import_ca_body_msp_ca_model_dict = ImportCaBodyMspCa.from_dict(import_ca_body_msp_ca_model_json).__dict__
        import_ca_body_msp_ca_model2 = ImportCaBodyMspCa(**import_ca_body_msp_ca_model_dict)

        # Verify the model instances are equivalent
        assert import_ca_body_msp_ca_model == import_ca_body_msp_ca_model2

        # Convert model instance back to dict and verify no loss of data
        import_ca_body_msp_ca_model_json2 = import_ca_body_msp_ca_model.to_dict()
        assert import_ca_body_msp_ca_model_json2 == import_ca_body_msp_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for ImportCaBodyMspComponent
#-----------------------------------------------------------------------------
class TestImportCaBodyMspComponent():

    #--------------------------------------------------------
    # Test serialization/deserialization for ImportCaBodyMspComponent
    #--------------------------------------------------------
    def test_import_ca_body_msp_component_serialization(self):

        # Construct a json representation of a ImportCaBodyMspComponent model
        import_ca_body_msp_component_model_json = {}
        import_ca_body_msp_component_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='

        # Construct a model instance of ImportCaBodyMspComponent by calling from_dict on the json representation
        import_ca_body_msp_component_model = ImportCaBodyMspComponent.from_dict(import_ca_body_msp_component_model_json)
        assert import_ca_body_msp_component_model != False

        # Construct a model instance of ImportCaBodyMspComponent by calling from_dict on the json representation
        import_ca_body_msp_component_model_dict = ImportCaBodyMspComponent.from_dict(import_ca_body_msp_component_model_json).__dict__
        import_ca_body_msp_component_model2 = ImportCaBodyMspComponent(**import_ca_body_msp_component_model_dict)

        # Verify the model instances are equivalent
        assert import_ca_body_msp_component_model == import_ca_body_msp_component_model2

        # Convert model instance back to dict and verify no loss of data
        import_ca_body_msp_component_model_json2 = import_ca_body_msp_component_model.to_dict()
        assert import_ca_body_msp_component_model_json2 == import_ca_body_msp_component_model_json

#-----------------------------------------------------------------------------
# Test Class for ImportCaBodyMspTlsca
#-----------------------------------------------------------------------------
class TestImportCaBodyMspTlsca():

    #--------------------------------------------------------
    # Test serialization/deserialization for ImportCaBodyMspTlsca
    #--------------------------------------------------------
    def test_import_ca_body_msp_tlsca_serialization(self):

        # Construct a json representation of a ImportCaBodyMspTlsca model
        import_ca_body_msp_tlsca_model_json = {}
        import_ca_body_msp_tlsca_model_json['name'] = 'org1tlsCA'
        import_ca_body_msp_tlsca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of ImportCaBodyMspTlsca by calling from_dict on the json representation
        import_ca_body_msp_tlsca_model = ImportCaBodyMspTlsca.from_dict(import_ca_body_msp_tlsca_model_json)
        assert import_ca_body_msp_tlsca_model != False

        # Construct a model instance of ImportCaBodyMspTlsca by calling from_dict on the json representation
        import_ca_body_msp_tlsca_model_dict = ImportCaBodyMspTlsca.from_dict(import_ca_body_msp_tlsca_model_json).__dict__
        import_ca_body_msp_tlsca_model2 = ImportCaBodyMspTlsca(**import_ca_body_msp_tlsca_model_dict)

        # Verify the model instances are equivalent
        assert import_ca_body_msp_tlsca_model == import_ca_body_msp_tlsca_model2

        # Convert model instance back to dict and verify no loss of data
        import_ca_body_msp_tlsca_model_json2 = import_ca_body_msp_tlsca_model.to_dict()
        assert import_ca_body_msp_tlsca_model_json2 == import_ca_body_msp_tlsca_model_json

#-----------------------------------------------------------------------------
# Test Class for LogSettingsResponse
#-----------------------------------------------------------------------------
class TestLogSettingsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for LogSettingsResponse
    #--------------------------------------------------------
    def test_log_settings_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        logging_settings_client_model = {} # LoggingSettingsClient
        logging_settings_client_model['enabled'] = True
        logging_settings_client_model['level'] = 'silly'
        logging_settings_client_model['unique_name'] = False

        logging_settings_server_model = {} # LoggingSettingsServer
        logging_settings_server_model['enabled'] = True
        logging_settings_server_model['level'] = 'silly'
        logging_settings_server_model['unique_name'] = False

        # Construct a json representation of a LogSettingsResponse model
        log_settings_response_model_json = {}
        log_settings_response_model_json['client'] = logging_settings_client_model
        log_settings_response_model_json['server'] = logging_settings_server_model

        # Construct a model instance of LogSettingsResponse by calling from_dict on the json representation
        log_settings_response_model = LogSettingsResponse.from_dict(log_settings_response_model_json)
        assert log_settings_response_model != False

        # Construct a model instance of LogSettingsResponse by calling from_dict on the json representation
        log_settings_response_model_dict = LogSettingsResponse.from_dict(log_settings_response_model_json).__dict__
        log_settings_response_model2 = LogSettingsResponse(**log_settings_response_model_dict)

        # Verify the model instances are equivalent
        assert log_settings_response_model == log_settings_response_model2

        # Convert model instance back to dict and verify no loss of data
        log_settings_response_model_json2 = log_settings_response_model.to_dict()
        assert log_settings_response_model_json2 == log_settings_response_model_json

#-----------------------------------------------------------------------------
# Test Class for LoggingSettingsClient
#-----------------------------------------------------------------------------
class TestLoggingSettingsClient():

    #--------------------------------------------------------
    # Test serialization/deserialization for LoggingSettingsClient
    #--------------------------------------------------------
    def test_logging_settings_client_serialization(self):

        # Construct a json representation of a LoggingSettingsClient model
        logging_settings_client_model_json = {}
        logging_settings_client_model_json['enabled'] = True
        logging_settings_client_model_json['level'] = 'silly'
        logging_settings_client_model_json['unique_name'] = False

        # Construct a model instance of LoggingSettingsClient by calling from_dict on the json representation
        logging_settings_client_model = LoggingSettingsClient.from_dict(logging_settings_client_model_json)
        assert logging_settings_client_model != False

        # Construct a model instance of LoggingSettingsClient by calling from_dict on the json representation
        logging_settings_client_model_dict = LoggingSettingsClient.from_dict(logging_settings_client_model_json).__dict__
        logging_settings_client_model2 = LoggingSettingsClient(**logging_settings_client_model_dict)

        # Verify the model instances are equivalent
        assert logging_settings_client_model == logging_settings_client_model2

        # Convert model instance back to dict and verify no loss of data
        logging_settings_client_model_json2 = logging_settings_client_model.to_dict()
        assert logging_settings_client_model_json2 == logging_settings_client_model_json

#-----------------------------------------------------------------------------
# Test Class for LoggingSettingsServer
#-----------------------------------------------------------------------------
class TestLoggingSettingsServer():

    #--------------------------------------------------------
    # Test serialization/deserialization for LoggingSettingsServer
    #--------------------------------------------------------
    def test_logging_settings_server_serialization(self):

        # Construct a json representation of a LoggingSettingsServer model
        logging_settings_server_model_json = {}
        logging_settings_server_model_json['enabled'] = True
        logging_settings_server_model_json['level'] = 'silly'
        logging_settings_server_model_json['unique_name'] = False

        # Construct a model instance of LoggingSettingsServer by calling from_dict on the json representation
        logging_settings_server_model = LoggingSettingsServer.from_dict(logging_settings_server_model_json)
        assert logging_settings_server_model != False

        # Construct a model instance of LoggingSettingsServer by calling from_dict on the json representation
        logging_settings_server_model_dict = LoggingSettingsServer.from_dict(logging_settings_server_model_json).__dict__
        logging_settings_server_model2 = LoggingSettingsServer(**logging_settings_server_model_dict)

        # Verify the model instances are equivalent
        assert logging_settings_server_model == logging_settings_server_model2

        # Convert model instance back to dict and verify no loss of data
        logging_settings_server_model_json2 = logging_settings_server_model.to_dict()
        assert logging_settings_server_model_json2 == logging_settings_server_model_json

#-----------------------------------------------------------------------------
# Test Class for Metrics
#-----------------------------------------------------------------------------
class TestMetrics():

    #--------------------------------------------------------
    # Test serialization/deserialization for Metrics
    #--------------------------------------------------------
    def test_metrics_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        # Construct a json representation of a Metrics model
        metrics_model_json = {}
        metrics_model_json['provider'] = 'prometheus'
        metrics_model_json['statsd'] = metrics_statsd_model

        # Construct a model instance of Metrics by calling from_dict on the json representation
        metrics_model = Metrics.from_dict(metrics_model_json)
        assert metrics_model != False

        # Construct a model instance of Metrics by calling from_dict on the json representation
        metrics_model_dict = Metrics.from_dict(metrics_model_json).__dict__
        metrics_model2 = Metrics(**metrics_model_dict)

        # Verify the model instances are equivalent
        assert metrics_model == metrics_model2

        # Convert model instance back to dict and verify no loss of data
        metrics_model_json2 = metrics_model.to_dict()
        assert metrics_model_json2 == metrics_model_json

#-----------------------------------------------------------------------------
# Test Class for MetricsStatsd
#-----------------------------------------------------------------------------
class TestMetricsStatsd():

    #--------------------------------------------------------
    # Test serialization/deserialization for MetricsStatsd
    #--------------------------------------------------------
    def test_metrics_statsd_serialization(self):

        # Construct a json representation of a MetricsStatsd model
        metrics_statsd_model_json = {}
        metrics_statsd_model_json['network'] = 'udp'
        metrics_statsd_model_json['address'] = '127.0.0.1:8125'
        metrics_statsd_model_json['writeInterval'] = '10s'
        metrics_statsd_model_json['prefix'] = 'server'

        # Construct a model instance of MetricsStatsd by calling from_dict on the json representation
        metrics_statsd_model = MetricsStatsd.from_dict(metrics_statsd_model_json)
        assert metrics_statsd_model != False

        # Construct a model instance of MetricsStatsd by calling from_dict on the json representation
        metrics_statsd_model_dict = MetricsStatsd.from_dict(metrics_statsd_model_json).__dict__
        metrics_statsd_model2 = MetricsStatsd(**metrics_statsd_model_dict)

        # Verify the model instances are equivalent
        assert metrics_statsd_model == metrics_statsd_model2

        # Convert model instance back to dict and verify no loss of data
        metrics_statsd_model_json2 = metrics_statsd_model.to_dict()
        assert metrics_statsd_model_json2 == metrics_statsd_model_json

#-----------------------------------------------------------------------------
# Test Class for MspCryptoCa
#-----------------------------------------------------------------------------
class TestMspCryptoCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspCryptoCa
    #--------------------------------------------------------
    def test_msp_crypto_ca_serialization(self):

        # Construct a json representation of a MspCryptoCa model
        msp_crypto_ca_model_json = {}
        msp_crypto_ca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_ca_model_json['ca_intermediate_certs'] = ['testString']

        # Construct a model instance of MspCryptoCa by calling from_dict on the json representation
        msp_crypto_ca_model = MspCryptoCa.from_dict(msp_crypto_ca_model_json)
        assert msp_crypto_ca_model != False

        # Construct a model instance of MspCryptoCa by calling from_dict on the json representation
        msp_crypto_ca_model_dict = MspCryptoCa.from_dict(msp_crypto_ca_model_json).__dict__
        msp_crypto_ca_model2 = MspCryptoCa(**msp_crypto_ca_model_dict)

        # Verify the model instances are equivalent
        assert msp_crypto_ca_model == msp_crypto_ca_model2

        # Convert model instance back to dict and verify no loss of data
        msp_crypto_ca_model_json2 = msp_crypto_ca_model.to_dict()
        assert msp_crypto_ca_model_json2 == msp_crypto_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for MspCryptoComp
#-----------------------------------------------------------------------------
class TestMspCryptoComp():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspCryptoComp
    #--------------------------------------------------------
    def test_msp_crypto_comp_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a json representation of a MspCryptoComp model
        msp_crypto_comp_model_json = {}
        msp_crypto_comp_model_json['ekey'] = 'testString'
        msp_crypto_comp_model_json['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model_json['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_crypto_comp_model_json['tls_key'] = 'testString'
        msp_crypto_comp_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_comp_model_json['client_auth'] = client_auth_model

        # Construct a model instance of MspCryptoComp by calling from_dict on the json representation
        msp_crypto_comp_model = MspCryptoComp.from_dict(msp_crypto_comp_model_json)
        assert msp_crypto_comp_model != False

        # Construct a model instance of MspCryptoComp by calling from_dict on the json representation
        msp_crypto_comp_model_dict = MspCryptoComp.from_dict(msp_crypto_comp_model_json).__dict__
        msp_crypto_comp_model2 = MspCryptoComp(**msp_crypto_comp_model_dict)

        # Verify the model instances are equivalent
        assert msp_crypto_comp_model == msp_crypto_comp_model2

        # Convert model instance back to dict and verify no loss of data
        msp_crypto_comp_model_json2 = msp_crypto_comp_model.to_dict()
        assert msp_crypto_comp_model_json2 == msp_crypto_comp_model_json

#-----------------------------------------------------------------------------
# Test Class for MspCryptoFieldCa
#-----------------------------------------------------------------------------
class TestMspCryptoFieldCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspCryptoFieldCa
    #--------------------------------------------------------
    def test_msp_crypto_field_ca_serialization(self):

        # Construct a json representation of a MspCryptoFieldCa model
        msp_crypto_field_ca_model_json = {}
        msp_crypto_field_ca_model_json['name'] = 'ca'
        msp_crypto_field_ca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of MspCryptoFieldCa by calling from_dict on the json representation
        msp_crypto_field_ca_model = MspCryptoFieldCa.from_dict(msp_crypto_field_ca_model_json)
        assert msp_crypto_field_ca_model != False

        # Construct a model instance of MspCryptoFieldCa by calling from_dict on the json representation
        msp_crypto_field_ca_model_dict = MspCryptoFieldCa.from_dict(msp_crypto_field_ca_model_json).__dict__
        msp_crypto_field_ca_model2 = MspCryptoFieldCa(**msp_crypto_field_ca_model_dict)

        # Verify the model instances are equivalent
        assert msp_crypto_field_ca_model == msp_crypto_field_ca_model2

        # Convert model instance back to dict and verify no loss of data
        msp_crypto_field_ca_model_json2 = msp_crypto_field_ca_model.to_dict()
        assert msp_crypto_field_ca_model_json2 == msp_crypto_field_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for MspCryptoFieldComponent
#-----------------------------------------------------------------------------
class TestMspCryptoFieldComponent():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspCryptoFieldComponent
    #--------------------------------------------------------
    def test_msp_crypto_field_component_serialization(self):

        # Construct a json representation of a MspCryptoFieldComponent model
        msp_crypto_field_component_model_json = {}
        msp_crypto_field_component_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model_json['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model_json['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of MspCryptoFieldComponent by calling from_dict on the json representation
        msp_crypto_field_component_model = MspCryptoFieldComponent.from_dict(msp_crypto_field_component_model_json)
        assert msp_crypto_field_component_model != False

        # Construct a model instance of MspCryptoFieldComponent by calling from_dict on the json representation
        msp_crypto_field_component_model_dict = MspCryptoFieldComponent.from_dict(msp_crypto_field_component_model_json).__dict__
        msp_crypto_field_component_model2 = MspCryptoFieldComponent(**msp_crypto_field_component_model_dict)

        # Verify the model instances are equivalent
        assert msp_crypto_field_component_model == msp_crypto_field_component_model2

        # Convert model instance back to dict and verify no loss of data
        msp_crypto_field_component_model_json2 = msp_crypto_field_component_model.to_dict()
        assert msp_crypto_field_component_model_json2 == msp_crypto_field_component_model_json

#-----------------------------------------------------------------------------
# Test Class for MspCryptoFieldTlsca
#-----------------------------------------------------------------------------
class TestMspCryptoFieldTlsca():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspCryptoFieldTlsca
    #--------------------------------------------------------
    def test_msp_crypto_field_tlsca_serialization(self):

        # Construct a json representation of a MspCryptoFieldTlsca model
        msp_crypto_field_tlsca_model_json = {}
        msp_crypto_field_tlsca_model_json['name'] = 'tlsca'
        msp_crypto_field_tlsca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of MspCryptoFieldTlsca by calling from_dict on the json representation
        msp_crypto_field_tlsca_model = MspCryptoFieldTlsca.from_dict(msp_crypto_field_tlsca_model_json)
        assert msp_crypto_field_tlsca_model != False

        # Construct a model instance of MspCryptoFieldTlsca by calling from_dict on the json representation
        msp_crypto_field_tlsca_model_dict = MspCryptoFieldTlsca.from_dict(msp_crypto_field_tlsca_model_json).__dict__
        msp_crypto_field_tlsca_model2 = MspCryptoFieldTlsca(**msp_crypto_field_tlsca_model_dict)

        # Verify the model instances are equivalent
        assert msp_crypto_field_tlsca_model == msp_crypto_field_tlsca_model2

        # Convert model instance back to dict and verify no loss of data
        msp_crypto_field_tlsca_model_json2 = msp_crypto_field_tlsca_model.to_dict()
        assert msp_crypto_field_tlsca_model_json2 == msp_crypto_field_tlsca_model_json

#-----------------------------------------------------------------------------
# Test Class for MspPublicData
#-----------------------------------------------------------------------------
class TestMspPublicData():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspPublicData
    #--------------------------------------------------------
    def test_msp_public_data_serialization(self):

        # Construct a json representation of a MspPublicData model
        msp_public_data_model_json = {}
        msp_public_data_model_json['msp_id'] = 'Org1'
        msp_public_data_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_public_data_model_json['admins'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_public_data_model_json['tls_root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of MspPublicData by calling from_dict on the json representation
        msp_public_data_model = MspPublicData.from_dict(msp_public_data_model_json)
        assert msp_public_data_model != False

        # Construct a model instance of MspPublicData by calling from_dict on the json representation
        msp_public_data_model_dict = MspPublicData.from_dict(msp_public_data_model_json).__dict__
        msp_public_data_model2 = MspPublicData(**msp_public_data_model_dict)

        # Verify the model instances are equivalent
        assert msp_public_data_model == msp_public_data_model2

        # Convert model instance back to dict and verify no loss of data
        msp_public_data_model_json2 = msp_public_data_model.to_dict()
        assert msp_public_data_model_json2 == msp_public_data_model_json

#-----------------------------------------------------------------------------
# Test Class for MspResponse
#-----------------------------------------------------------------------------
class TestMspResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspResponse
    #--------------------------------------------------------
    def test_msp_response_serialization(self):

        # Construct a json representation of a MspResponse model
        msp_response_model_json = {}
        msp_response_model_json['id'] = 'component-1'
        msp_response_model_json['type'] = 'fabric-peer'
        msp_response_model_json['display_name'] = 'My Peer'
        msp_response_model_json['msp_id'] = 'Org1'
        msp_response_model_json['timestamp'] = 1537262855753
        msp_response_model_json['tags'] = ['fabric-ca']
        msp_response_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_response_model_json['intermediate_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkRhdGEgaGVyZSBpZiB0aGlzIHdhcyByZWFsCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K']
        msp_response_model_json['admins'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        msp_response_model_json['scheme_version'] = 'v1'
        msp_response_model_json['tls_root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a model instance of MspResponse by calling from_dict on the json representation
        msp_response_model = MspResponse.from_dict(msp_response_model_json)
        assert msp_response_model != False

        # Construct a model instance of MspResponse by calling from_dict on the json representation
        msp_response_model_dict = MspResponse.from_dict(msp_response_model_json).__dict__
        msp_response_model2 = MspResponse(**msp_response_model_dict)

        # Verify the model instances are equivalent
        assert msp_response_model == msp_response_model2

        # Convert model instance back to dict and verify no loss of data
        msp_response_model_json2 = msp_response_model.to_dict()
        assert msp_response_model_json2 == msp_response_model_json

#-----------------------------------------------------------------------------
# Test Class for NotificationData
#-----------------------------------------------------------------------------
class TestNotificationData():

    #--------------------------------------------------------
    # Test serialization/deserialization for NotificationData
    #--------------------------------------------------------
    def test_notification_data_serialization(self):

        # Construct a json representation of a NotificationData model
        notification_data_model_json = {}
        notification_data_model_json['id'] = '60d84819bfa17adb4174ff3a1c52b5d6'
        notification_data_model_json['type'] = 'notification'
        notification_data_model_json['status'] = 'pending'
        notification_data_model_json['by'] = 'd******a@us.ibm.com'
        notification_data_model_json['message'] = 'Restarting application'
        notification_data_model_json['ts_display'] = 1537262855753

        # Construct a model instance of NotificationData by calling from_dict on the json representation
        notification_data_model = NotificationData.from_dict(notification_data_model_json)
        assert notification_data_model != False

        # Construct a model instance of NotificationData by calling from_dict on the json representation
        notification_data_model_dict = NotificationData.from_dict(notification_data_model_json).__dict__
        notification_data_model2 = NotificationData(**notification_data_model_dict)

        # Verify the model instances are equivalent
        assert notification_data_model == notification_data_model2

        # Convert model instance back to dict and verify no loss of data
        notification_data_model_json2 = notification_data_model.to_dict()
        assert notification_data_model_json2 == notification_data_model_json

#-----------------------------------------------------------------------------
# Test Class for OrdererResponse
#-----------------------------------------------------------------------------
class TestOrdererResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for OrdererResponse
    #--------------------------------------------------------
    def test_orderer_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        msp_crypto_field_ca_model = {} # MspCryptoFieldCa
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_component_model = {} # MspCryptoFieldComponent
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_tlsca_model = {} # MspCryptoFieldTlsca
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        msp_crypto_field_model = {} # MspCryptoField
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        node_ou_model = {} # NodeOu
        node_ou_model['enabled'] = True

        orderer_response_resources_model = {} # OrdererResponseResources
        orderer_response_resources_model['orderer'] = generic_resources_model
        orderer_response_resources_model['proxy'] = generic_resources_model

        orderer_response_storage_model = {} # OrdererResponseStorage
        orderer_response_storage_model['orderer'] = storage_object_model

        # Construct a json representation of a OrdererResponse model
        orderer_response_model_json = {}
        orderer_response_model_json['id'] = 'component-1'
        orderer_response_model_json['dep_component_id'] = 'admin'
        orderer_response_model_json['api_url'] = 'grpcs://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:7050'
        orderer_response_model_json['display_name'] = 'orderer'
        orderer_response_model_json['grpcwp_url'] = 'https://n3a3ec3-myorderer-proxy.ibp.us-south.containers.appdomain.cloud:443'
        orderer_response_model_json['location'] = 'ibmcloud'
        orderer_response_model_json['operations_url'] = 'https://n3a3ec3-myorderer.ibp.us-south.containers.appdomain.cloud:8443'
        orderer_response_model_json['orderer_type'] = 'raft'
        orderer_response_model_json['config_override'] = { 'foo': 'bar' }
        orderer_response_model_json['consenter_proposal_fin'] = True
        orderer_response_model_json['node_ou'] = node_ou_model
        orderer_response_model_json['msp'] = msp_crypto_field_model
        orderer_response_model_json['msp_id'] = 'Org1'
        orderer_response_model_json['resources'] = orderer_response_resources_model
        orderer_response_model_json['scheme_version'] = 'v1'
        orderer_response_model_json['storage'] = orderer_response_storage_model
        orderer_response_model_json['system_channel_id'] = 'testchainid'
        orderer_response_model_json['tags'] = ['fabric-ca']
        orderer_response_model_json['timestamp'] = 1537262855753
        orderer_response_model_json['type'] = 'fabric-peer'
        orderer_response_model_json['version'] = '1.4.6-1'
        orderer_response_model_json['zone'] = '-'

        # Construct a model instance of OrdererResponse by calling from_dict on the json representation
        orderer_response_model = OrdererResponse.from_dict(orderer_response_model_json)
        assert orderer_response_model != False

        # Construct a model instance of OrdererResponse by calling from_dict on the json representation
        orderer_response_model_dict = OrdererResponse.from_dict(orderer_response_model_json).__dict__
        orderer_response_model2 = OrdererResponse(**orderer_response_model_dict)

        # Verify the model instances are equivalent
        assert orderer_response_model == orderer_response_model2

        # Convert model instance back to dict and verify no loss of data
        orderer_response_model_json2 = orderer_response_model.to_dict()
        assert orderer_response_model_json2 == orderer_response_model_json

#-----------------------------------------------------------------------------
# Test Class for OrdererResponseResources
#-----------------------------------------------------------------------------
class TestOrdererResponseResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for OrdererResponseResources
    #--------------------------------------------------------
    def test_orderer_response_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        # Construct a json representation of a OrdererResponseResources model
        orderer_response_resources_model_json = {}
        orderer_response_resources_model_json['orderer'] = generic_resources_model
        orderer_response_resources_model_json['proxy'] = generic_resources_model

        # Construct a model instance of OrdererResponseResources by calling from_dict on the json representation
        orderer_response_resources_model = OrdererResponseResources.from_dict(orderer_response_resources_model_json)
        assert orderer_response_resources_model != False

        # Construct a model instance of OrdererResponseResources by calling from_dict on the json representation
        orderer_response_resources_model_dict = OrdererResponseResources.from_dict(orderer_response_resources_model_json).__dict__
        orderer_response_resources_model2 = OrdererResponseResources(**orderer_response_resources_model_dict)

        # Verify the model instances are equivalent
        assert orderer_response_resources_model == orderer_response_resources_model2

        # Convert model instance back to dict and verify no loss of data
        orderer_response_resources_model_json2 = orderer_response_resources_model.to_dict()
        assert orderer_response_resources_model_json2 == orderer_response_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for OrdererResponseStorage
#-----------------------------------------------------------------------------
class TestOrdererResponseStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for OrdererResponseStorage
    #--------------------------------------------------------
    def test_orderer_response_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a OrdererResponseStorage model
        orderer_response_storage_model_json = {}
        orderer_response_storage_model_json['orderer'] = storage_object_model

        # Construct a model instance of OrdererResponseStorage by calling from_dict on the json representation
        orderer_response_storage_model = OrdererResponseStorage.from_dict(orderer_response_storage_model_json)
        assert orderer_response_storage_model != False

        # Construct a model instance of OrdererResponseStorage by calling from_dict on the json representation
        orderer_response_storage_model_dict = OrdererResponseStorage.from_dict(orderer_response_storage_model_json).__dict__
        orderer_response_storage_model2 = OrdererResponseStorage(**orderer_response_storage_model_dict)

        # Verify the model instances are equivalent
        assert orderer_response_storage_model == orderer_response_storage_model2

        # Convert model instance back to dict and verify no loss of data
        orderer_response_storage_model_json2 = orderer_response_storage_model.to_dict()
        assert orderer_response_storage_model_json2 == orderer_response_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for PeerResources
#-----------------------------------------------------------------------------
class TestPeerResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for PeerResources
    #--------------------------------------------------------
    def test_peer_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        resource_object_model = {} # ResourceObject
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        resource_object_couch_db_model = {} # ResourceObjectCouchDb
        resource_object_couch_db_model['requests'] = resource_requests_model
        resource_object_couch_db_model['limits'] = resource_limits_model

        resource_object_fab_v1_model = {} # ResourceObjectFabV1
        resource_object_fab_v1_model['requests'] = resource_requests_model
        resource_object_fab_v1_model['limits'] = resource_limits_model

        resource_object_fab_v2_model = {} # ResourceObjectFabV2
        resource_object_fab_v2_model['requests'] = resource_requests_model
        resource_object_fab_v2_model['limits'] = resource_limits_model

        # Construct a json representation of a PeerResources model
        peer_resources_model_json = {}
        peer_resources_model_json['chaincodelauncher'] = resource_object_fab_v2_model
        peer_resources_model_json['couchdb'] = resource_object_couch_db_model
        peer_resources_model_json['statedb'] = resource_object_model
        peer_resources_model_json['dind'] = resource_object_fab_v1_model
        peer_resources_model_json['fluentd'] = resource_object_fab_v1_model
        peer_resources_model_json['peer'] = resource_object_model
        peer_resources_model_json['proxy'] = resource_object_model

        # Construct a model instance of PeerResources by calling from_dict on the json representation
        peer_resources_model = PeerResources.from_dict(peer_resources_model_json)
        assert peer_resources_model != False

        # Construct a model instance of PeerResources by calling from_dict on the json representation
        peer_resources_model_dict = PeerResources.from_dict(peer_resources_model_json).__dict__
        peer_resources_model2 = PeerResources(**peer_resources_model_dict)

        # Verify the model instances are equivalent
        assert peer_resources_model == peer_resources_model2

        # Convert model instance back to dict and verify no loss of data
        peer_resources_model_json2 = peer_resources_model.to_dict()
        assert peer_resources_model_json2 == peer_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for PeerResponse
#-----------------------------------------------------------------------------
class TestPeerResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for PeerResponse
    #--------------------------------------------------------
    def test_peer_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        msp_crypto_field_ca_model = {} # MspCryptoFieldCa
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_component_model = {} # MspCryptoFieldComponent
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_tlsca_model = {} # MspCryptoFieldTlsca
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        msp_crypto_field_model = {} # MspCryptoField
        msp_crypto_field_model['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model['component'] = msp_crypto_field_component_model

        node_ou_model = {} # NodeOu
        node_ou_model['enabled'] = True

        peer_response_resources_model = {} # PeerResponseResources
        peer_response_resources_model['peer'] = generic_resources_model
        peer_response_resources_model['proxy'] = generic_resources_model
        peer_response_resources_model['statedb'] = generic_resources_model

        peer_response_storage_model = {} # PeerResponseStorage
        peer_response_storage_model['peer'] = storage_object_model
        peer_response_storage_model['statedb'] = storage_object_model

        # Construct a json representation of a PeerResponse model
        peer_response_model_json = {}
        peer_response_model_json['id'] = 'component-1'
        peer_response_model_json['dep_component_id'] = 'admin'
        peer_response_model_json['api_url'] = 'grpcs://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:7051'
        peer_response_model_json['display_name'] = 'My Peer'
        peer_response_model_json['grpcwp_url'] = 'https://n3a3ec3-mypeer-proxy.ibp.us-south.containers.appdomain.cloud:8084'
        peer_response_model_json['location'] = 'ibmcloud'
        peer_response_model_json['operations_url'] = 'https://n3a3ec3-mypeer.ibp.us-south.containers.appdomain.cloud:9443'
        peer_response_model_json['config_override'] = { 'foo': 'bar' }
        peer_response_model_json['node_ou'] = node_ou_model
        peer_response_model_json['msp'] = msp_crypto_field_model
        peer_response_model_json['msp_id'] = 'Org1'
        peer_response_model_json['resources'] = peer_response_resources_model
        peer_response_model_json['scheme_version'] = 'v1'
        peer_response_model_json['state_db'] = 'couchdb'
        peer_response_model_json['storage'] = peer_response_storage_model
        peer_response_model_json['tags'] = ['fabric-ca']
        peer_response_model_json['timestamp'] = 1537262855753
        peer_response_model_json['type'] = 'fabric-peer'
        peer_response_model_json['version'] = '1.4.6-1'
        peer_response_model_json['zone'] = '-'

        # Construct a model instance of PeerResponse by calling from_dict on the json representation
        peer_response_model = PeerResponse.from_dict(peer_response_model_json)
        assert peer_response_model != False

        # Construct a model instance of PeerResponse by calling from_dict on the json representation
        peer_response_model_dict = PeerResponse.from_dict(peer_response_model_json).__dict__
        peer_response_model2 = PeerResponse(**peer_response_model_dict)

        # Verify the model instances are equivalent
        assert peer_response_model == peer_response_model2

        # Convert model instance back to dict and verify no loss of data
        peer_response_model_json2 = peer_response_model.to_dict()
        assert peer_response_model_json2 == peer_response_model_json

#-----------------------------------------------------------------------------
# Test Class for PeerResponseResources
#-----------------------------------------------------------------------------
class TestPeerResponseResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for PeerResponseResources
    #--------------------------------------------------------
    def test_peer_response_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        generic_resource_limits_model = {} # GenericResourceLimits
        generic_resource_limits_model['cpu'] = '8000m'
        generic_resource_limits_model['memory'] = '16384M'

        generic_resources_requests_model = {} # GenericResourcesRequests
        generic_resources_requests_model['cpu'] = '100m'
        generic_resources_requests_model['memory'] = '256M'

        generic_resources_model = {} # GenericResources
        generic_resources_model['requests'] = generic_resources_requests_model
        generic_resources_model['limits'] = generic_resource_limits_model

        # Construct a json representation of a PeerResponseResources model
        peer_response_resources_model_json = {}
        peer_response_resources_model_json['peer'] = generic_resources_model
        peer_response_resources_model_json['proxy'] = generic_resources_model
        peer_response_resources_model_json['statedb'] = generic_resources_model

        # Construct a model instance of PeerResponseResources by calling from_dict on the json representation
        peer_response_resources_model = PeerResponseResources.from_dict(peer_response_resources_model_json)
        assert peer_response_resources_model != False

        # Construct a model instance of PeerResponseResources by calling from_dict on the json representation
        peer_response_resources_model_dict = PeerResponseResources.from_dict(peer_response_resources_model_json).__dict__
        peer_response_resources_model2 = PeerResponseResources(**peer_response_resources_model_dict)

        # Verify the model instances are equivalent
        assert peer_response_resources_model == peer_response_resources_model2

        # Convert model instance back to dict and verify no loss of data
        peer_response_resources_model_json2 = peer_response_resources_model.to_dict()
        assert peer_response_resources_model_json2 == peer_response_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for PeerResponseStorage
#-----------------------------------------------------------------------------
class TestPeerResponseStorage():

    #--------------------------------------------------------
    # Test serialization/deserialization for PeerResponseStorage
    #--------------------------------------------------------
    def test_peer_response_storage_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        storage_object_model = {} # StorageObject
        storage_object_model['size'] = '4GiB'
        storage_object_model['class'] = 'default'

        # Construct a json representation of a PeerResponseStorage model
        peer_response_storage_model_json = {}
        peer_response_storage_model_json['peer'] = storage_object_model
        peer_response_storage_model_json['statedb'] = storage_object_model

        # Construct a model instance of PeerResponseStorage by calling from_dict on the json representation
        peer_response_storage_model = PeerResponseStorage.from_dict(peer_response_storage_model_json)
        assert peer_response_storage_model != False

        # Construct a model instance of PeerResponseStorage by calling from_dict on the json representation
        peer_response_storage_model_dict = PeerResponseStorage.from_dict(peer_response_storage_model_json).__dict__
        peer_response_storage_model2 = PeerResponseStorage(**peer_response_storage_model_dict)

        # Verify the model instances are equivalent
        assert peer_response_storage_model == peer_response_storage_model2

        # Convert model instance back to dict and verify no loss of data
        peer_response_storage_model_json2 = peer_response_storage_model.to_dict()
        assert peer_response_storage_model_json2 == peer_response_storage_model_json

#-----------------------------------------------------------------------------
# Test Class for RemoveMultiComponentsResponse
#-----------------------------------------------------------------------------
class TestRemoveMultiComponentsResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for RemoveMultiComponentsResponse
    #--------------------------------------------------------
    def test_remove_multi_components_response_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        delete_component_response_model = {} # DeleteComponentResponse
        delete_component_response_model['message'] = 'deleted'
        delete_component_response_model['type'] = 'fabric-peer'
        delete_component_response_model['id'] = 'component-1'
        delete_component_response_model['display_name'] = 'My Peer'

        # Construct a json representation of a RemoveMultiComponentsResponse model
        remove_multi_components_response_model_json = {}
        remove_multi_components_response_model_json['removed'] = [delete_component_response_model]

        # Construct a model instance of RemoveMultiComponentsResponse by calling from_dict on the json representation
        remove_multi_components_response_model = RemoveMultiComponentsResponse.from_dict(remove_multi_components_response_model_json)
        assert remove_multi_components_response_model != False

        # Construct a model instance of RemoveMultiComponentsResponse by calling from_dict on the json representation
        remove_multi_components_response_model_dict = RemoveMultiComponentsResponse.from_dict(remove_multi_components_response_model_json).__dict__
        remove_multi_components_response_model2 = RemoveMultiComponentsResponse(**remove_multi_components_response_model_dict)

        # Verify the model instances are equivalent
        assert remove_multi_components_response_model == remove_multi_components_response_model2

        # Convert model instance back to dict and verify no loss of data
        remove_multi_components_response_model_json2 = remove_multi_components_response_model.to_dict()
        assert remove_multi_components_response_model_json2 == remove_multi_components_response_model_json

#-----------------------------------------------------------------------------
# Test Class for ResourceLimits
#-----------------------------------------------------------------------------
class TestResourceLimits():

    #--------------------------------------------------------
    # Test serialization/deserialization for ResourceLimits
    #--------------------------------------------------------
    def test_resource_limits_serialization(self):

        # Construct a json representation of a ResourceLimits model
        resource_limits_model_json = {}
        resource_limits_model_json['cpu'] = '100m'
        resource_limits_model_json['memory'] = '256MiB'

        # Construct a model instance of ResourceLimits by calling from_dict on the json representation
        resource_limits_model = ResourceLimits.from_dict(resource_limits_model_json)
        assert resource_limits_model != False

        # Construct a model instance of ResourceLimits by calling from_dict on the json representation
        resource_limits_model_dict = ResourceLimits.from_dict(resource_limits_model_json).__dict__
        resource_limits_model2 = ResourceLimits(**resource_limits_model_dict)

        # Verify the model instances are equivalent
        assert resource_limits_model == resource_limits_model2

        # Convert model instance back to dict and verify no loss of data
        resource_limits_model_json2 = resource_limits_model.to_dict()
        assert resource_limits_model_json2 == resource_limits_model_json

#-----------------------------------------------------------------------------
# Test Class for ResourceObject
#-----------------------------------------------------------------------------
class TestResourceObject():

    #--------------------------------------------------------
    # Test serialization/deserialization for ResourceObject
    #--------------------------------------------------------
    def test_resource_object_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a json representation of a ResourceObject model
        resource_object_model_json = {}
        resource_object_model_json['requests'] = resource_requests_model
        resource_object_model_json['limits'] = resource_limits_model

        # Construct a model instance of ResourceObject by calling from_dict on the json representation
        resource_object_model = ResourceObject.from_dict(resource_object_model_json)
        assert resource_object_model != False

        # Construct a model instance of ResourceObject by calling from_dict on the json representation
        resource_object_model_dict = ResourceObject.from_dict(resource_object_model_json).__dict__
        resource_object_model2 = ResourceObject(**resource_object_model_dict)

        # Verify the model instances are equivalent
        assert resource_object_model == resource_object_model2

        # Convert model instance back to dict and verify no loss of data
        resource_object_model_json2 = resource_object_model.to_dict()
        assert resource_object_model_json2 == resource_object_model_json

#-----------------------------------------------------------------------------
# Test Class for ResourceObjectCouchDb
#-----------------------------------------------------------------------------
class TestResourceObjectCouchDb():

    #--------------------------------------------------------
    # Test serialization/deserialization for ResourceObjectCouchDb
    #--------------------------------------------------------
    def test_resource_object_couch_db_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a json representation of a ResourceObjectCouchDb model
        resource_object_couch_db_model_json = {}
        resource_object_couch_db_model_json['requests'] = resource_requests_model
        resource_object_couch_db_model_json['limits'] = resource_limits_model

        # Construct a model instance of ResourceObjectCouchDb by calling from_dict on the json representation
        resource_object_couch_db_model = ResourceObjectCouchDb.from_dict(resource_object_couch_db_model_json)
        assert resource_object_couch_db_model != False

        # Construct a model instance of ResourceObjectCouchDb by calling from_dict on the json representation
        resource_object_couch_db_model_dict = ResourceObjectCouchDb.from_dict(resource_object_couch_db_model_json).__dict__
        resource_object_couch_db_model2 = ResourceObjectCouchDb(**resource_object_couch_db_model_dict)

        # Verify the model instances are equivalent
        assert resource_object_couch_db_model == resource_object_couch_db_model2

        # Convert model instance back to dict and verify no loss of data
        resource_object_couch_db_model_json2 = resource_object_couch_db_model.to_dict()
        assert resource_object_couch_db_model_json2 == resource_object_couch_db_model_json

#-----------------------------------------------------------------------------
# Test Class for ResourceObjectFabV1
#-----------------------------------------------------------------------------
class TestResourceObjectFabV1():

    #--------------------------------------------------------
    # Test serialization/deserialization for ResourceObjectFabV1
    #--------------------------------------------------------
    def test_resource_object_fab_v1_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a json representation of a ResourceObjectFabV1 model
        resource_object_fab_v1_model_json = {}
        resource_object_fab_v1_model_json['requests'] = resource_requests_model
        resource_object_fab_v1_model_json['limits'] = resource_limits_model

        # Construct a model instance of ResourceObjectFabV1 by calling from_dict on the json representation
        resource_object_fab_v1_model = ResourceObjectFabV1.from_dict(resource_object_fab_v1_model_json)
        assert resource_object_fab_v1_model != False

        # Construct a model instance of ResourceObjectFabV1 by calling from_dict on the json representation
        resource_object_fab_v1_model_dict = ResourceObjectFabV1.from_dict(resource_object_fab_v1_model_json).__dict__
        resource_object_fab_v1_model2 = ResourceObjectFabV1(**resource_object_fab_v1_model_dict)

        # Verify the model instances are equivalent
        assert resource_object_fab_v1_model == resource_object_fab_v1_model2

        # Convert model instance back to dict and verify no loss of data
        resource_object_fab_v1_model_json2 = resource_object_fab_v1_model.to_dict()
        assert resource_object_fab_v1_model_json2 == resource_object_fab_v1_model_json

#-----------------------------------------------------------------------------
# Test Class for ResourceObjectFabV2
#-----------------------------------------------------------------------------
class TestResourceObjectFabV2():

    #--------------------------------------------------------
    # Test serialization/deserialization for ResourceObjectFabV2
    #--------------------------------------------------------
    def test_resource_object_fab_v2_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        # Construct a json representation of a ResourceObjectFabV2 model
        resource_object_fab_v2_model_json = {}
        resource_object_fab_v2_model_json['requests'] = resource_requests_model
        resource_object_fab_v2_model_json['limits'] = resource_limits_model

        # Construct a model instance of ResourceObjectFabV2 by calling from_dict on the json representation
        resource_object_fab_v2_model = ResourceObjectFabV2.from_dict(resource_object_fab_v2_model_json)
        assert resource_object_fab_v2_model != False

        # Construct a model instance of ResourceObjectFabV2 by calling from_dict on the json representation
        resource_object_fab_v2_model_dict = ResourceObjectFabV2.from_dict(resource_object_fab_v2_model_json).__dict__
        resource_object_fab_v2_model2 = ResourceObjectFabV2(**resource_object_fab_v2_model_dict)

        # Verify the model instances are equivalent
        assert resource_object_fab_v2_model == resource_object_fab_v2_model2

        # Convert model instance back to dict and verify no loss of data
        resource_object_fab_v2_model_json2 = resource_object_fab_v2_model.to_dict()
        assert resource_object_fab_v2_model_json2 == resource_object_fab_v2_model_json

#-----------------------------------------------------------------------------
# Test Class for ResourceRequests
#-----------------------------------------------------------------------------
class TestResourceRequests():

    #--------------------------------------------------------
    # Test serialization/deserialization for ResourceRequests
    #--------------------------------------------------------
    def test_resource_requests_serialization(self):

        # Construct a json representation of a ResourceRequests model
        resource_requests_model_json = {}
        resource_requests_model_json['cpu'] = '100m'
        resource_requests_model_json['memory'] = '256MiB'

        # Construct a model instance of ResourceRequests by calling from_dict on the json representation
        resource_requests_model = ResourceRequests.from_dict(resource_requests_model_json)
        assert resource_requests_model != False

        # Construct a model instance of ResourceRequests by calling from_dict on the json representation
        resource_requests_model_dict = ResourceRequests.from_dict(resource_requests_model_json).__dict__
        resource_requests_model2 = ResourceRequests(**resource_requests_model_dict)

        # Verify the model instances are equivalent
        assert resource_requests_model == resource_requests_model2

        # Convert model instance back to dict and verify no loss of data
        resource_requests_model_json2 = resource_requests_model.to_dict()
        assert resource_requests_model_json2 == resource_requests_model_json

#-----------------------------------------------------------------------------
# Test Class for RestartAthenaResponse
#-----------------------------------------------------------------------------
class TestRestartAthenaResponse():

    #--------------------------------------------------------
    # Test serialization/deserialization for RestartAthenaResponse
    #--------------------------------------------------------
    def test_restart_athena_response_serialization(self):

        # Construct a json representation of a RestartAthenaResponse model
        restart_athena_response_model_json = {}
        restart_athena_response_model_json['message'] = 'restarting - give me 5-30 seconds'

        # Construct a model instance of RestartAthenaResponse by calling from_dict on the json representation
        restart_athena_response_model = RestartAthenaResponse.from_dict(restart_athena_response_model_json)
        assert restart_athena_response_model != False

        # Construct a model instance of RestartAthenaResponse by calling from_dict on the json representation
        restart_athena_response_model_dict = RestartAthenaResponse.from_dict(restart_athena_response_model_json).__dict__
        restart_athena_response_model2 = RestartAthenaResponse(**restart_athena_response_model_dict)

        # Verify the model instances are equivalent
        assert restart_athena_response_model == restart_athena_response_model2

        # Convert model instance back to dict and verify no loss of data
        restart_athena_response_model_json2 = restart_athena_response_model.to_dict()
        assert restart_athena_response_model_json2 == restart_athena_response_model_json

#-----------------------------------------------------------------------------
# Test Class for SettingsTimestampData
#-----------------------------------------------------------------------------
class TestSettingsTimestampData():

    #--------------------------------------------------------
    # Test serialization/deserialization for SettingsTimestampData
    #--------------------------------------------------------
    def test_settings_timestamp_data_serialization(self):

        # Construct a json representation of a SettingsTimestampData model
        settings_timestamp_data_model_json = {}
        settings_timestamp_data_model_json['now'] = 1542746836056
        settings_timestamp_data_model_json['born'] = 1542746836056
        settings_timestamp_data_model_json['next_settings_update'] = '1.2 mins'
        settings_timestamp_data_model_json['up_time'] = '30 days'

        # Construct a model instance of SettingsTimestampData by calling from_dict on the json representation
        settings_timestamp_data_model = SettingsTimestampData.from_dict(settings_timestamp_data_model_json)
        assert settings_timestamp_data_model != False

        # Construct a model instance of SettingsTimestampData by calling from_dict on the json representation
        settings_timestamp_data_model_dict = SettingsTimestampData.from_dict(settings_timestamp_data_model_json).__dict__
        settings_timestamp_data_model2 = SettingsTimestampData(**settings_timestamp_data_model_dict)

        # Verify the model instances are equivalent
        assert settings_timestamp_data_model == settings_timestamp_data_model2

        # Convert model instance back to dict and verify no loss of data
        settings_timestamp_data_model_json2 = settings_timestamp_data_model.to_dict()
        assert settings_timestamp_data_model_json2 == settings_timestamp_data_model_json

#-----------------------------------------------------------------------------
# Test Class for StorageObject
#-----------------------------------------------------------------------------
class TestStorageObject():

    #--------------------------------------------------------
    # Test serialization/deserialization for StorageObject
    #--------------------------------------------------------
    def test_storage_object_serialization(self):

        # Construct a json representation of a StorageObject model
        storage_object_model_json = {}
        storage_object_model_json['size'] = '4GiB'
        storage_object_model_json['class'] = 'default'

        # Construct a model instance of StorageObject by calling from_dict on the json representation
        storage_object_model = StorageObject.from_dict(storage_object_model_json)
        assert storage_object_model != False

        # Construct a model instance of StorageObject by calling from_dict on the json representation
        storage_object_model_dict = StorageObject.from_dict(storage_object_model_json).__dict__
        storage_object_model2 = StorageObject(**storage_object_model_dict)

        # Verify the model instances are equivalent
        assert storage_object_model == storage_object_model2

        # Convert model instance back to dict and verify no loss of data
        storage_object_model_json2 = storage_object_model.to_dict()
        assert storage_object_model_json2 == storage_object_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateCaBodyConfigOverride
#-----------------------------------------------------------------------------
class TestUpdateCaBodyConfigOverride():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateCaBodyConfigOverride
    #--------------------------------------------------------
    def test_update_ca_body_config_override_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        config_ca_db_tls_client_model = {} # ConfigCADbTlsClient
        config_ca_db_tls_client_model['certfile'] = 'testString'
        config_ca_db_tls_client_model['keyfile'] = 'testString'

        config_ca_intermediate_tls_client_model = {} # ConfigCAIntermediateTlsClient
        config_ca_intermediate_tls_client_model['certfile'] = 'testString'
        config_ca_intermediate_tls_client_model['keyfile'] = 'testString'

        identity_attrs_model = {} # IdentityAttrs
        identity_attrs_model['hf.Registrar.Roles'] = '*'
        identity_attrs_model['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model['hf.Revoker'] = True
        identity_attrs_model['hf.IntermediateCA'] = True
        identity_attrs_model['hf.GenCRL'] = True
        identity_attrs_model['hf.Registrar.Attributes'] = '*'
        identity_attrs_model['hf.AffiliationMgr'] = True

        bccsp_pkc_s11_model = {} # BccspPKCS11
        bccsp_pkc_s11_model['Label'] = 'testString'
        bccsp_pkc_s11_model['Pin'] = 'testString'
        bccsp_pkc_s11_model['Hash'] = 'SHA2'
        bccsp_pkc_s11_model['Security'] = 256

        bccsp_sw_model = {} # BccspSW
        bccsp_sw_model['Hash'] = 'SHA2'
        bccsp_sw_model['Security'] = 256

        config_ca_cfg_identities_model = {} # ConfigCACfgIdentities
        config_ca_cfg_identities_model['passwordattempts'] = 10
        config_ca_cfg_identities_model['allowremove'] = False

        config_ca_csr_ca_model = {} # ConfigCACsrCa
        config_ca_csr_ca_model['expiry'] = '131400h'
        config_ca_csr_ca_model['pathlength'] = 0

        config_ca_csr_keyrequest_model = {} # ConfigCACsrKeyrequest
        config_ca_csr_keyrequest_model['algo'] = 'ecdsa'
        config_ca_csr_keyrequest_model['size'] = 256

        config_ca_csr_names_item_model = {} # ConfigCACsrNamesItem
        config_ca_csr_names_item_model['C'] = 'US'
        config_ca_csr_names_item_model['ST'] = 'North Carolina'
        config_ca_csr_names_item_model['L'] = 'Raleigh'
        config_ca_csr_names_item_model['O'] = 'Hyperledger'
        config_ca_csr_names_item_model['OU'] = 'Fabric'

        config_ca_db_tls_model = {} # ConfigCADbTls
        config_ca_db_tls_model['certfiles'] = ['testString']
        config_ca_db_tls_model['client'] = config_ca_db_tls_client_model
        config_ca_db_tls_model['enabled'] = False

        config_ca_intermediate_enrollment_model = {} # ConfigCAIntermediateEnrollment
        config_ca_intermediate_enrollment_model['hosts'] = 'localhost'
        config_ca_intermediate_enrollment_model['profile'] = 'testString'
        config_ca_intermediate_enrollment_model['label'] = 'testString'

        config_ca_intermediate_parentserver_model = {} # ConfigCAIntermediateParentserver
        config_ca_intermediate_parentserver_model['url'] = 'testString'
        config_ca_intermediate_parentserver_model['caname'] = 'testString'

        config_ca_intermediate_tls_model = {} # ConfigCAIntermediateTls
        config_ca_intermediate_tls_model['certfiles'] = ['testString']
        config_ca_intermediate_tls_model['client'] = config_ca_intermediate_tls_client_model

        config_ca_registry_identities_item_model = {} # ConfigCARegistryIdentitiesItem
        config_ca_registry_identities_item_model['name'] = 'admin'
        config_ca_registry_identities_item_model['pass'] = 'password'
        config_ca_registry_identities_item_model['type'] = 'client'
        config_ca_registry_identities_item_model['maxenrollments'] = -1
        config_ca_registry_identities_item_model['affiliation'] = 'testString'
        config_ca_registry_identities_item_model['attrs'] = identity_attrs_model

        config_ca_tls_clientauth_model = {} # ConfigCATlsClientauth
        config_ca_tls_clientauth_model['type'] = 'noclientcert'
        config_ca_tls_clientauth_model['certfiles'] = ['testString']

        metrics_statsd_model = {} # MetricsStatsd
        metrics_statsd_model['network'] = 'udp'
        metrics_statsd_model['address'] = '127.0.0.1:8125'
        metrics_statsd_model['writeInterval'] = '10s'
        metrics_statsd_model['prefix'] = 'server'

        bccsp_model = {} # Bccsp
        bccsp_model['Default'] = 'SW'
        bccsp_model['SW'] = bccsp_sw_model
        bccsp_model['PKCS11'] = bccsp_pkc_s11_model

        config_ca_affiliations_model = {} # ConfigCAAffiliations
        config_ca_affiliations_model['org1'] = ['department1']
        config_ca_affiliations_model['org2'] = ['department1']
        config_ca_affiliations_model['foo'] = { 'foo': 'bar' }

        config_ca_ca_model = {} # ConfigCACa
        config_ca_ca_model['keyfile'] = 'testString'
        config_ca_ca_model['certfile'] = 'testString'
        config_ca_ca_model['chainfile'] = 'testString'

        config_ca_cfg_model = {} # ConfigCACfg
        config_ca_cfg_model['identities'] = config_ca_cfg_identities_model

        config_ca_cors_model = {} # ConfigCACors
        config_ca_cors_model['enabled'] = True
        config_ca_cors_model['origins'] = ['*']

        config_ca_crl_model = {} # ConfigCACrl
        config_ca_crl_model['expiry'] = '24h'

        config_ca_csr_model = {} # ConfigCACsr
        config_ca_csr_model['cn'] = 'ca'
        config_ca_csr_model['keyrequest'] = config_ca_csr_keyrequest_model
        config_ca_csr_model['names'] = [config_ca_csr_names_item_model]
        config_ca_csr_model['hosts'] = ['localhost']
        config_ca_csr_model['ca'] = config_ca_csr_ca_model

        config_ca_db_model = {} # ConfigCADb
        config_ca_db_model['type'] = 'postgres'
        config_ca_db_model['datasource'] = 'host=fake.databases.appdomain.cloud port=31941 user=ibm_cloud password=password dbname=ibmclouddb sslmode=verify-full'
        config_ca_db_model['tls'] = config_ca_db_tls_model

        config_ca_idemix_model = {} # ConfigCAIdemix
        config_ca_idemix_model['rhpoolsize'] = 100
        config_ca_idemix_model['nonceexpiration'] = '15s'
        config_ca_idemix_model['noncesweepinterval'] = '15m'

        config_ca_intermediate_model = {} # ConfigCAIntermediate
        config_ca_intermediate_model['parentserver'] = config_ca_intermediate_parentserver_model
        config_ca_intermediate_model['enrollment'] = config_ca_intermediate_enrollment_model
        config_ca_intermediate_model['tls'] = config_ca_intermediate_tls_model

        config_ca_registry_model = {} # ConfigCARegistry
        config_ca_registry_model['maxenrollments'] = -1
        config_ca_registry_model['identities'] = [config_ca_registry_identities_item_model]

        config_ca_tls_model = {} # ConfigCATls
        config_ca_tls_model['keyfile'] = 'testString'
        config_ca_tls_model['certfile'] = 'testString'
        config_ca_tls_model['clientauth'] = config_ca_tls_clientauth_model

        metrics_model = {} # Metrics
        metrics_model['provider'] = 'prometheus'
        metrics_model['statsd'] = metrics_statsd_model

        config_ca_update_model = {} # ConfigCAUpdate
        config_ca_update_model['cors'] = config_ca_cors_model
        config_ca_update_model['debug'] = False
        config_ca_update_model['crlsizelimit'] = 512000
        config_ca_update_model['tls'] = config_ca_tls_model
        config_ca_update_model['ca'] = config_ca_ca_model
        config_ca_update_model['crl'] = config_ca_crl_model
        config_ca_update_model['registry'] = config_ca_registry_model
        config_ca_update_model['db'] = config_ca_db_model
        config_ca_update_model['affiliations'] = config_ca_affiliations_model
        config_ca_update_model['csr'] = config_ca_csr_model
        config_ca_update_model['idemix'] = config_ca_idemix_model
        config_ca_update_model['BCCSP'] = bccsp_model
        config_ca_update_model['intermediate'] = config_ca_intermediate_model
        config_ca_update_model['cfg'] = config_ca_cfg_model
        config_ca_update_model['metrics'] = metrics_model

        # Construct a json representation of a UpdateCaBodyConfigOverride model
        update_ca_body_config_override_model_json = {}
        update_ca_body_config_override_model_json['ca'] = config_ca_update_model

        # Construct a model instance of UpdateCaBodyConfigOverride by calling from_dict on the json representation
        update_ca_body_config_override_model = UpdateCaBodyConfigOverride.from_dict(update_ca_body_config_override_model_json)
        assert update_ca_body_config_override_model != False

        # Construct a model instance of UpdateCaBodyConfigOverride by calling from_dict on the json representation
        update_ca_body_config_override_model_dict = UpdateCaBodyConfigOverride.from_dict(update_ca_body_config_override_model_json).__dict__
        update_ca_body_config_override_model2 = UpdateCaBodyConfigOverride(**update_ca_body_config_override_model_dict)

        # Verify the model instances are equivalent
        assert update_ca_body_config_override_model == update_ca_body_config_override_model2

        # Convert model instance back to dict and verify no loss of data
        update_ca_body_config_override_model_json2 = update_ca_body_config_override_model.to_dict()
        assert update_ca_body_config_override_model_json2 == update_ca_body_config_override_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateCaBodyResources
#-----------------------------------------------------------------------------
class TestUpdateCaBodyResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateCaBodyResources
    #--------------------------------------------------------
    def test_update_ca_body_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        resource_object_model = {} # ResourceObject
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a json representation of a UpdateCaBodyResources model
        update_ca_body_resources_model_json = {}
        update_ca_body_resources_model_json['ca'] = resource_object_model

        # Construct a model instance of UpdateCaBodyResources by calling from_dict on the json representation
        update_ca_body_resources_model = UpdateCaBodyResources.from_dict(update_ca_body_resources_model_json)
        assert update_ca_body_resources_model != False

        # Construct a model instance of UpdateCaBodyResources by calling from_dict on the json representation
        update_ca_body_resources_model_dict = UpdateCaBodyResources.from_dict(update_ca_body_resources_model_json).__dict__
        update_ca_body_resources_model2 = UpdateCaBodyResources(**update_ca_body_resources_model_dict)

        # Verify the model instances are equivalent
        assert update_ca_body_resources_model == update_ca_body_resources_model2

        # Convert model instance back to dict and verify no loss of data
        update_ca_body_resources_model_json2 = update_ca_body_resources_model.to_dict()
        assert update_ca_body_resources_model_json2 == update_ca_body_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateEnrollmentCryptoField
#-----------------------------------------------------------------------------
class TestUpdateEnrollmentCryptoField():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateEnrollmentCryptoField
    #--------------------------------------------------------
    def test_update_enrollment_crypto_field_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        crypto_enrollment_component_model = {} # CryptoEnrollmentComponent
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        update_enrollment_crypto_field_ca_model = {} # UpdateEnrollmentCryptoFieldCa
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        update_enrollment_crypto_field_tlsca_model = {} # UpdateEnrollmentCryptoFieldTlsca
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        # Construct a json representation of a UpdateEnrollmentCryptoField model
        update_enrollment_crypto_field_model_json = {}
        update_enrollment_crypto_field_model_json['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model_json['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model_json['tlsca'] = update_enrollment_crypto_field_tlsca_model

        # Construct a model instance of UpdateEnrollmentCryptoField by calling from_dict on the json representation
        update_enrollment_crypto_field_model = UpdateEnrollmentCryptoField.from_dict(update_enrollment_crypto_field_model_json)
        assert update_enrollment_crypto_field_model != False

        # Construct a model instance of UpdateEnrollmentCryptoField by calling from_dict on the json representation
        update_enrollment_crypto_field_model_dict = UpdateEnrollmentCryptoField.from_dict(update_enrollment_crypto_field_model_json).__dict__
        update_enrollment_crypto_field_model2 = UpdateEnrollmentCryptoField(**update_enrollment_crypto_field_model_dict)

        # Verify the model instances are equivalent
        assert update_enrollment_crypto_field_model == update_enrollment_crypto_field_model2

        # Convert model instance back to dict and verify no loss of data
        update_enrollment_crypto_field_model_json2 = update_enrollment_crypto_field_model.to_dict()
        assert update_enrollment_crypto_field_model_json2 == update_enrollment_crypto_field_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateEnrollmentCryptoFieldCa
#-----------------------------------------------------------------------------
class TestUpdateEnrollmentCryptoFieldCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateEnrollmentCryptoFieldCa
    #--------------------------------------------------------
    def test_update_enrollment_crypto_field_ca_serialization(self):

        # Construct a json representation of a UpdateEnrollmentCryptoFieldCa model
        update_enrollment_crypto_field_ca_model_json = {}
        update_enrollment_crypto_field_ca_model_json['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model_json['port'] = 7054
        update_enrollment_crypto_field_ca_model_json['name'] = 'ca'
        update_enrollment_crypto_field_ca_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model_json['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model_json['enroll_secret'] = 'password'

        # Construct a model instance of UpdateEnrollmentCryptoFieldCa by calling from_dict on the json representation
        update_enrollment_crypto_field_ca_model = UpdateEnrollmentCryptoFieldCa.from_dict(update_enrollment_crypto_field_ca_model_json)
        assert update_enrollment_crypto_field_ca_model != False

        # Construct a model instance of UpdateEnrollmentCryptoFieldCa by calling from_dict on the json representation
        update_enrollment_crypto_field_ca_model_dict = UpdateEnrollmentCryptoFieldCa.from_dict(update_enrollment_crypto_field_ca_model_json).__dict__
        update_enrollment_crypto_field_ca_model2 = UpdateEnrollmentCryptoFieldCa(**update_enrollment_crypto_field_ca_model_dict)

        # Verify the model instances are equivalent
        assert update_enrollment_crypto_field_ca_model == update_enrollment_crypto_field_ca_model2

        # Convert model instance back to dict and verify no loss of data
        update_enrollment_crypto_field_ca_model_json2 = update_enrollment_crypto_field_ca_model.to_dict()
        assert update_enrollment_crypto_field_ca_model_json2 == update_enrollment_crypto_field_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateEnrollmentCryptoFieldTlsca
#-----------------------------------------------------------------------------
class TestUpdateEnrollmentCryptoFieldTlsca():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateEnrollmentCryptoFieldTlsca
    #--------------------------------------------------------
    def test_update_enrollment_crypto_field_tlsca_serialization(self):

        # Construct a json representation of a UpdateEnrollmentCryptoFieldTlsca model
        update_enrollment_crypto_field_tlsca_model_json = {}
        update_enrollment_crypto_field_tlsca_model_json['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model_json['port'] = 7054
        update_enrollment_crypto_field_tlsca_model_json['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model_json['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model_json['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model_json['csr_hosts'] = ['testString']

        # Construct a model instance of UpdateEnrollmentCryptoFieldTlsca by calling from_dict on the json representation
        update_enrollment_crypto_field_tlsca_model = UpdateEnrollmentCryptoFieldTlsca.from_dict(update_enrollment_crypto_field_tlsca_model_json)
        assert update_enrollment_crypto_field_tlsca_model != False

        # Construct a model instance of UpdateEnrollmentCryptoFieldTlsca by calling from_dict on the json representation
        update_enrollment_crypto_field_tlsca_model_dict = UpdateEnrollmentCryptoFieldTlsca.from_dict(update_enrollment_crypto_field_tlsca_model_json).__dict__
        update_enrollment_crypto_field_tlsca_model2 = UpdateEnrollmentCryptoFieldTlsca(**update_enrollment_crypto_field_tlsca_model_dict)

        # Verify the model instances are equivalent
        assert update_enrollment_crypto_field_tlsca_model == update_enrollment_crypto_field_tlsca_model2

        # Convert model instance back to dict and verify no loss of data
        update_enrollment_crypto_field_tlsca_model_json2 = update_enrollment_crypto_field_tlsca_model.to_dict()
        assert update_enrollment_crypto_field_tlsca_model_json2 == update_enrollment_crypto_field_tlsca_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateMspCryptoField
#-----------------------------------------------------------------------------
class TestUpdateMspCryptoField():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateMspCryptoField
    #--------------------------------------------------------
    def test_update_msp_crypto_field_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        update_msp_crypto_field_ca_model = {} # UpdateMspCryptoFieldCa
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        update_msp_crypto_field_component_model = {} # UpdateMspCryptoFieldComponent
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        update_msp_crypto_field_tlsca_model = {} # UpdateMspCryptoFieldTlsca
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        # Construct a json representation of a UpdateMspCryptoField model
        update_msp_crypto_field_model_json = {}
        update_msp_crypto_field_model_json['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model_json['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model_json['component'] = update_msp_crypto_field_component_model

        # Construct a model instance of UpdateMspCryptoField by calling from_dict on the json representation
        update_msp_crypto_field_model = UpdateMspCryptoField.from_dict(update_msp_crypto_field_model_json)
        assert update_msp_crypto_field_model != False

        # Construct a model instance of UpdateMspCryptoField by calling from_dict on the json representation
        update_msp_crypto_field_model_dict = UpdateMspCryptoField.from_dict(update_msp_crypto_field_model_json).__dict__
        update_msp_crypto_field_model2 = UpdateMspCryptoField(**update_msp_crypto_field_model_dict)

        # Verify the model instances are equivalent
        assert update_msp_crypto_field_model == update_msp_crypto_field_model2

        # Convert model instance back to dict and verify no loss of data
        update_msp_crypto_field_model_json2 = update_msp_crypto_field_model.to_dict()
        assert update_msp_crypto_field_model_json2 == update_msp_crypto_field_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateMspCryptoFieldCa
#-----------------------------------------------------------------------------
class TestUpdateMspCryptoFieldCa():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateMspCryptoFieldCa
    #--------------------------------------------------------
    def test_update_msp_crypto_field_ca_serialization(self):

        # Construct a json representation of a UpdateMspCryptoFieldCa model
        update_msp_crypto_field_ca_model_json = {}
        update_msp_crypto_field_ca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model_json['ca_intermediate_certs'] = ['testString']

        # Construct a model instance of UpdateMspCryptoFieldCa by calling from_dict on the json representation
        update_msp_crypto_field_ca_model = UpdateMspCryptoFieldCa.from_dict(update_msp_crypto_field_ca_model_json)
        assert update_msp_crypto_field_ca_model != False

        # Construct a model instance of UpdateMspCryptoFieldCa by calling from_dict on the json representation
        update_msp_crypto_field_ca_model_dict = UpdateMspCryptoFieldCa.from_dict(update_msp_crypto_field_ca_model_json).__dict__
        update_msp_crypto_field_ca_model2 = UpdateMspCryptoFieldCa(**update_msp_crypto_field_ca_model_dict)

        # Verify the model instances are equivalent
        assert update_msp_crypto_field_ca_model == update_msp_crypto_field_ca_model2

        # Convert model instance back to dict and verify no loss of data
        update_msp_crypto_field_ca_model_json2 = update_msp_crypto_field_ca_model.to_dict()
        assert update_msp_crypto_field_ca_model_json2 == update_msp_crypto_field_ca_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateMspCryptoFieldComponent
#-----------------------------------------------------------------------------
class TestUpdateMspCryptoFieldComponent():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateMspCryptoFieldComponent
    #--------------------------------------------------------
    def test_update_msp_crypto_field_component_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        # Construct a json representation of a UpdateMspCryptoFieldComponent model
        update_msp_crypto_field_component_model_json = {}
        update_msp_crypto_field_component_model_json['ekey'] = 'testString'
        update_msp_crypto_field_component_model_json['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model_json['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model_json['tls_key'] = 'testString'
        update_msp_crypto_field_component_model_json['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model_json['client_auth'] = client_auth_model

        # Construct a model instance of UpdateMspCryptoFieldComponent by calling from_dict on the json representation
        update_msp_crypto_field_component_model = UpdateMspCryptoFieldComponent.from_dict(update_msp_crypto_field_component_model_json)
        assert update_msp_crypto_field_component_model != False

        # Construct a model instance of UpdateMspCryptoFieldComponent by calling from_dict on the json representation
        update_msp_crypto_field_component_model_dict = UpdateMspCryptoFieldComponent.from_dict(update_msp_crypto_field_component_model_json).__dict__
        update_msp_crypto_field_component_model2 = UpdateMspCryptoFieldComponent(**update_msp_crypto_field_component_model_dict)

        # Verify the model instances are equivalent
        assert update_msp_crypto_field_component_model == update_msp_crypto_field_component_model2

        # Convert model instance back to dict and verify no loss of data
        update_msp_crypto_field_component_model_json2 = update_msp_crypto_field_component_model.to_dict()
        assert update_msp_crypto_field_component_model_json2 == update_msp_crypto_field_component_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateMspCryptoFieldTlsca
#-----------------------------------------------------------------------------
class TestUpdateMspCryptoFieldTlsca():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateMspCryptoFieldTlsca
    #--------------------------------------------------------
    def test_update_msp_crypto_field_tlsca_serialization(self):

        # Construct a json representation of a UpdateMspCryptoFieldTlsca model
        update_msp_crypto_field_tlsca_model_json = {}
        update_msp_crypto_field_tlsca_model_json['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model_json['ca_intermediate_certs'] = ['testString']

        # Construct a model instance of UpdateMspCryptoFieldTlsca by calling from_dict on the json representation
        update_msp_crypto_field_tlsca_model = UpdateMspCryptoFieldTlsca.from_dict(update_msp_crypto_field_tlsca_model_json)
        assert update_msp_crypto_field_tlsca_model != False

        # Construct a model instance of UpdateMspCryptoFieldTlsca by calling from_dict on the json representation
        update_msp_crypto_field_tlsca_model_dict = UpdateMspCryptoFieldTlsca.from_dict(update_msp_crypto_field_tlsca_model_json).__dict__
        update_msp_crypto_field_tlsca_model2 = UpdateMspCryptoFieldTlsca(**update_msp_crypto_field_tlsca_model_dict)

        # Verify the model instances are equivalent
        assert update_msp_crypto_field_tlsca_model == update_msp_crypto_field_tlsca_model2

        # Convert model instance back to dict and verify no loss of data
        update_msp_crypto_field_tlsca_model_json2 = update_msp_crypto_field_tlsca_model.to_dict()
        assert update_msp_crypto_field_tlsca_model_json2 == update_msp_crypto_field_tlsca_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateOrdererBodyCrypto
#-----------------------------------------------------------------------------
class TestUpdateOrdererBodyCrypto():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateOrdererBodyCrypto
    #--------------------------------------------------------
    def test_update_orderer_body_crypto_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        crypto_enrollment_component_model = {} # CryptoEnrollmentComponent
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        update_enrollment_crypto_field_ca_model = {} # UpdateEnrollmentCryptoFieldCa
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        update_enrollment_crypto_field_tlsca_model = {} # UpdateEnrollmentCryptoFieldTlsca
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        update_msp_crypto_field_ca_model = {} # UpdateMspCryptoFieldCa
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        update_msp_crypto_field_component_model = {} # UpdateMspCryptoFieldComponent
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        update_msp_crypto_field_tlsca_model = {} # UpdateMspCryptoFieldTlsca
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        update_enrollment_crypto_field_model = {} # UpdateEnrollmentCryptoField
        update_enrollment_crypto_field_model['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model['tlsca'] = update_enrollment_crypto_field_tlsca_model

        update_msp_crypto_field_model = {} # UpdateMspCryptoField
        update_msp_crypto_field_model['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model['component'] = update_msp_crypto_field_component_model

        # Construct a json representation of a UpdateOrdererBodyCrypto model
        update_orderer_body_crypto_model_json = {}
        update_orderer_body_crypto_model_json['enrollment'] = update_enrollment_crypto_field_model
        update_orderer_body_crypto_model_json['msp'] = update_msp_crypto_field_model

        # Construct a model instance of UpdateOrdererBodyCrypto by calling from_dict on the json representation
        update_orderer_body_crypto_model = UpdateOrdererBodyCrypto.from_dict(update_orderer_body_crypto_model_json)
        assert update_orderer_body_crypto_model != False

        # Construct a model instance of UpdateOrdererBodyCrypto by calling from_dict on the json representation
        update_orderer_body_crypto_model_dict = UpdateOrdererBodyCrypto.from_dict(update_orderer_body_crypto_model_json).__dict__
        update_orderer_body_crypto_model2 = UpdateOrdererBodyCrypto(**update_orderer_body_crypto_model_dict)

        # Verify the model instances are equivalent
        assert update_orderer_body_crypto_model == update_orderer_body_crypto_model2

        # Convert model instance back to dict and verify no loss of data
        update_orderer_body_crypto_model_json2 = update_orderer_body_crypto_model.to_dict()
        assert update_orderer_body_crypto_model_json2 == update_orderer_body_crypto_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdateOrdererBodyResources
#-----------------------------------------------------------------------------
class TestUpdateOrdererBodyResources():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdateOrdererBodyResources
    #--------------------------------------------------------
    def test_update_orderer_body_resources_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        resource_limits_model = {} # ResourceLimits
        resource_limits_model['cpu'] = '100m'
        resource_limits_model['memory'] = '256MiB'

        resource_requests_model = {} # ResourceRequests
        resource_requests_model['cpu'] = '100m'
        resource_requests_model['memory'] = '256MiB'

        resource_object_model = {} # ResourceObject
        resource_object_model['requests'] = resource_requests_model
        resource_object_model['limits'] = resource_limits_model

        # Construct a json representation of a UpdateOrdererBodyResources model
        update_orderer_body_resources_model_json = {}
        update_orderer_body_resources_model_json['orderer'] = resource_object_model
        update_orderer_body_resources_model_json['proxy'] = resource_object_model

        # Construct a model instance of UpdateOrdererBodyResources by calling from_dict on the json representation
        update_orderer_body_resources_model = UpdateOrdererBodyResources.from_dict(update_orderer_body_resources_model_json)
        assert update_orderer_body_resources_model != False

        # Construct a model instance of UpdateOrdererBodyResources by calling from_dict on the json representation
        update_orderer_body_resources_model_dict = UpdateOrdererBodyResources.from_dict(update_orderer_body_resources_model_json).__dict__
        update_orderer_body_resources_model2 = UpdateOrdererBodyResources(**update_orderer_body_resources_model_dict)

        # Verify the model instances are equivalent
        assert update_orderer_body_resources_model == update_orderer_body_resources_model2

        # Convert model instance back to dict and verify no loss of data
        update_orderer_body_resources_model_json2 = update_orderer_body_resources_model.to_dict()
        assert update_orderer_body_resources_model_json2 == update_orderer_body_resources_model_json

#-----------------------------------------------------------------------------
# Test Class for UpdatePeerBodyCrypto
#-----------------------------------------------------------------------------
class TestUpdatePeerBodyCrypto():

    #--------------------------------------------------------
    # Test serialization/deserialization for UpdatePeerBodyCrypto
    #--------------------------------------------------------
    def test_update_peer_body_crypto_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        client_auth_model = {} # ClientAuth
        client_auth_model['type'] = 'noclientcert'
        client_auth_model['tls_certs'] = ['testString']

        crypto_enrollment_component_model = {} # CryptoEnrollmentComponent
        crypto_enrollment_component_model['admincerts'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        update_enrollment_crypto_field_ca_model = {} # UpdateEnrollmentCryptoFieldCa
        update_enrollment_crypto_field_ca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_ca_model['port'] = 7054
        update_enrollment_crypto_field_ca_model['name'] = 'ca'
        update_enrollment_crypto_field_ca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_ca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_ca_model['enroll_secret'] = 'password'

        update_enrollment_crypto_field_tlsca_model = {} # UpdateEnrollmentCryptoFieldTlsca
        update_enrollment_crypto_field_tlsca_model['host'] = 'n3a3ec3-myca.ibp.us-south.containers.appdomain.cloud'
        update_enrollment_crypto_field_tlsca_model['port'] = 7054
        update_enrollment_crypto_field_tlsca_model['name'] = 'tlsca'
        update_enrollment_crypto_field_tlsca_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_enrollment_crypto_field_tlsca_model['enroll_id'] = 'admin'
        update_enrollment_crypto_field_tlsca_model['enroll_secret'] = 'password'
        update_enrollment_crypto_field_tlsca_model['csr_hosts'] = ['testString']

        update_msp_crypto_field_ca_model = {} # UpdateMspCryptoFieldCa
        update_msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_ca_model['ca_intermediate_certs'] = ['testString']

        update_msp_crypto_field_component_model = {} # UpdateMspCryptoFieldComponent
        update_msp_crypto_field_component_model['ekey'] = 'testString'
        update_msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_component_model['tls_key'] = 'testString'
        update_msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        update_msp_crypto_field_component_model['client_auth'] = client_auth_model

        update_msp_crypto_field_tlsca_model = {} # UpdateMspCryptoFieldTlsca
        update_msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']
        update_msp_crypto_field_tlsca_model['ca_intermediate_certs'] = ['testString']

        update_enrollment_crypto_field_model = {} # UpdateEnrollmentCryptoField
        update_enrollment_crypto_field_model['component'] = crypto_enrollment_component_model
        update_enrollment_crypto_field_model['ca'] = update_enrollment_crypto_field_ca_model
        update_enrollment_crypto_field_model['tlsca'] = update_enrollment_crypto_field_tlsca_model

        update_msp_crypto_field_model = {} # UpdateMspCryptoField
        update_msp_crypto_field_model['ca'] = update_msp_crypto_field_ca_model
        update_msp_crypto_field_model['tlsca'] = update_msp_crypto_field_tlsca_model
        update_msp_crypto_field_model['component'] = update_msp_crypto_field_component_model

        # Construct a json representation of a UpdatePeerBodyCrypto model
        update_peer_body_crypto_model_json = {}
        update_peer_body_crypto_model_json['enrollment'] = update_enrollment_crypto_field_model
        update_peer_body_crypto_model_json['msp'] = update_msp_crypto_field_model

        # Construct a model instance of UpdatePeerBodyCrypto by calling from_dict on the json representation
        update_peer_body_crypto_model = UpdatePeerBodyCrypto.from_dict(update_peer_body_crypto_model_json)
        assert update_peer_body_crypto_model != False

        # Construct a model instance of UpdatePeerBodyCrypto by calling from_dict on the json representation
        update_peer_body_crypto_model_dict = UpdatePeerBodyCrypto.from_dict(update_peer_body_crypto_model_json).__dict__
        update_peer_body_crypto_model2 = UpdatePeerBodyCrypto(**update_peer_body_crypto_model_dict)

        # Verify the model instances are equivalent
        assert update_peer_body_crypto_model == update_peer_body_crypto_model2

        # Convert model instance back to dict and verify no loss of data
        update_peer_body_crypto_model_json2 = update_peer_body_crypto_model.to_dict()
        assert update_peer_body_crypto_model_json2 == update_peer_body_crypto_model_json

#-----------------------------------------------------------------------------
# Test Class for ActionEnroll
#-----------------------------------------------------------------------------
class TestActionEnroll():

    #--------------------------------------------------------
    # Test serialization/deserialization for ActionEnroll
    #--------------------------------------------------------
    def test_action_enroll_serialization(self):

        # Construct a json representation of a ActionEnroll model
        action_enroll_model_json = {}
        action_enroll_model_json['tls_cert'] = True
        action_enroll_model_json['ecert'] = True

        # Construct a model instance of ActionEnroll by calling from_dict on the json representation
        action_enroll_model = ActionEnroll.from_dict(action_enroll_model_json)
        assert action_enroll_model != False

        # Construct a model instance of ActionEnroll by calling from_dict on the json representation
        action_enroll_model_dict = ActionEnroll.from_dict(action_enroll_model_json).__dict__
        action_enroll_model2 = ActionEnroll(**action_enroll_model_dict)

        # Verify the model instances are equivalent
        assert action_enroll_model == action_enroll_model2

        # Convert model instance back to dict and verify no loss of data
        action_enroll_model_json2 = action_enroll_model.to_dict()
        assert action_enroll_model_json2 == action_enroll_model_json

#-----------------------------------------------------------------------------
# Test Class for ActionReenroll
#-----------------------------------------------------------------------------
class TestActionReenroll():

    #--------------------------------------------------------
    # Test serialization/deserialization for ActionReenroll
    #--------------------------------------------------------
    def test_action_reenroll_serialization(self):

        # Construct a json representation of a ActionReenroll model
        action_reenroll_model_json = {}
        action_reenroll_model_json['tls_cert'] = True
        action_reenroll_model_json['ecert'] = True

        # Construct a model instance of ActionReenroll by calling from_dict on the json representation
        action_reenroll_model = ActionReenroll.from_dict(action_reenroll_model_json)
        assert action_reenroll_model != False

        # Construct a model instance of ActionReenroll by calling from_dict on the json representation
        action_reenroll_model_dict = ActionReenroll.from_dict(action_reenroll_model_json).__dict__
        action_reenroll_model2 = ActionReenroll(**action_reenroll_model_dict)

        # Verify the model instances are equivalent
        assert action_reenroll_model == action_reenroll_model2

        # Convert model instance back to dict and verify no loss of data
        action_reenroll_model_json2 = action_reenroll_model.to_dict()
        assert action_reenroll_model_json2 == action_reenroll_model_json

#-----------------------------------------------------------------------------
# Test Class for ActionRenew
#-----------------------------------------------------------------------------
class TestActionRenew():

    #--------------------------------------------------------
    # Test serialization/deserialization for ActionRenew
    #--------------------------------------------------------
    def test_action_renew_serialization(self):

        # Construct a json representation of a ActionRenew model
        action_renew_model_json = {}
        action_renew_model_json['tls_cert'] = True

        # Construct a model instance of ActionRenew by calling from_dict on the json representation
        action_renew_model = ActionRenew.from_dict(action_renew_model_json)
        assert action_renew_model != False

        # Construct a model instance of ActionRenew by calling from_dict on the json representation
        action_renew_model_dict = ActionRenew.from_dict(action_renew_model_json).__dict__
        action_renew_model2 = ActionRenew(**action_renew_model_dict)

        # Verify the model instances are equivalent
        assert action_renew_model == action_renew_model2

        # Convert model instance back to dict and verify no loss of data
        action_renew_model_json2 = action_renew_model.to_dict()
        assert action_renew_model_json2 == action_renew_model_json

#-----------------------------------------------------------------------------
# Test Class for ClientAuth
#-----------------------------------------------------------------------------
class TestClientAuth():

    #--------------------------------------------------------
    # Test serialization/deserialization for ClientAuth
    #--------------------------------------------------------
    def test_client_auth_serialization(self):

        # Construct a json representation of a ClientAuth model
        client_auth_model_json = {}
        client_auth_model_json['type'] = 'noclientcert'
        client_auth_model_json['tls_certs'] = ['testString']

        # Construct a model instance of ClientAuth by calling from_dict on the json representation
        client_auth_model = ClientAuth.from_dict(client_auth_model_json)
        assert client_auth_model != False

        # Construct a model instance of ClientAuth by calling from_dict on the json representation
        client_auth_model_dict = ClientAuth.from_dict(client_auth_model_json).__dict__
        client_auth_model2 = ClientAuth(**client_auth_model_dict)

        # Verify the model instances are equivalent
        assert client_auth_model == client_auth_model2

        # Convert model instance back to dict and verify no loss of data
        client_auth_model_json2 = client_auth_model.to_dict()
        assert client_auth_model_json2 == client_auth_model_json

#-----------------------------------------------------------------------------
# Test Class for Hsm
#-----------------------------------------------------------------------------
class TestHsm():

    #--------------------------------------------------------
    # Test serialization/deserialization for Hsm
    #--------------------------------------------------------
    def test_hsm_serialization(self):

        # Construct a json representation of a Hsm model
        hsm_model_json = {}
        hsm_model_json['pkcs11endpoint'] = 'tcp://example.com:666'

        # Construct a model instance of Hsm by calling from_dict on the json representation
        hsm_model = Hsm.from_dict(hsm_model_json)
        assert hsm_model != False

        # Construct a model instance of Hsm by calling from_dict on the json representation
        hsm_model_dict = Hsm.from_dict(hsm_model_json).__dict__
        hsm_model2 = Hsm(**hsm_model_dict)

        # Verify the model instances are equivalent
        assert hsm_model == hsm_model2

        # Convert model instance back to dict and verify no loss of data
        hsm_model_json2 = hsm_model.to_dict()
        assert hsm_model_json2 == hsm_model_json

#-----------------------------------------------------------------------------
# Test Class for IdentityAttrs
#-----------------------------------------------------------------------------
class TestIdentityAttrs():

    #--------------------------------------------------------
    # Test serialization/deserialization for IdentityAttrs
    #--------------------------------------------------------
    def test_identity_attrs_serialization(self):

        # Construct a json representation of a IdentityAttrs model
        identity_attrs_model_json = {}
        identity_attrs_model_json['hf.Registrar.Roles'] = '*'
        identity_attrs_model_json['hf.Registrar.DelegateRoles'] = '*'
        identity_attrs_model_json['hf.Revoker'] = True
        identity_attrs_model_json['hf.IntermediateCA'] = True
        identity_attrs_model_json['hf.GenCRL'] = True
        identity_attrs_model_json['hf.Registrar.Attributes'] = '*'
        identity_attrs_model_json['hf.AffiliationMgr'] = True

        # Construct a model instance of IdentityAttrs by calling from_dict on the json representation
        identity_attrs_model = IdentityAttrs.from_dict(identity_attrs_model_json)
        assert identity_attrs_model != False

        # Construct a model instance of IdentityAttrs by calling from_dict on the json representation
        identity_attrs_model_dict = IdentityAttrs.from_dict(identity_attrs_model_json).__dict__
        identity_attrs_model2 = IdentityAttrs(**identity_attrs_model_dict)

        # Verify the model instances are equivalent
        assert identity_attrs_model == identity_attrs_model2

        # Convert model instance back to dict and verify no loss of data
        identity_attrs_model_json2 = identity_attrs_model.to_dict()
        assert identity_attrs_model_json2 == identity_attrs_model_json

#-----------------------------------------------------------------------------
# Test Class for MspCryptoField
#-----------------------------------------------------------------------------
class TestMspCryptoField():

    #--------------------------------------------------------
    # Test serialization/deserialization for MspCryptoField
    #--------------------------------------------------------
    def test_msp_crypto_field_serialization(self):

        # Construct dict forms of any model objects needed in order to build this model.

        msp_crypto_field_ca_model = {} # MspCryptoFieldCa
        msp_crypto_field_ca_model['name'] = 'ca'
        msp_crypto_field_ca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_component_model = {} # MspCryptoFieldComponent
        msp_crypto_field_component_model['tls_cert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['ecert'] = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo='
        msp_crypto_field_component_model['admin_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        msp_crypto_field_tlsca_model = {} # MspCryptoFieldTlsca
        msp_crypto_field_tlsca_model['name'] = 'tlsca'
        msp_crypto_field_tlsca_model['root_certs'] = ['LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNlcnQgZGF0YSB3b3VsZCBiZSBoZXJlIGlmIHRoaXMgd2FzIHJlYWwKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=']

        # Construct a json representation of a MspCryptoField model
        msp_crypto_field_model_json = {}
        msp_crypto_field_model_json['ca'] = msp_crypto_field_ca_model
        msp_crypto_field_model_json['tlsca'] = msp_crypto_field_tlsca_model
        msp_crypto_field_model_json['component'] = msp_crypto_field_component_model

        # Construct a model instance of MspCryptoField by calling from_dict on the json representation
        msp_crypto_field_model = MspCryptoField.from_dict(msp_crypto_field_model_json)
        assert msp_crypto_field_model != False

        # Construct a model instance of MspCryptoField by calling from_dict on the json representation
        msp_crypto_field_model_dict = MspCryptoField.from_dict(msp_crypto_field_model_json).__dict__
        msp_crypto_field_model2 = MspCryptoField(**msp_crypto_field_model_dict)

        # Verify the model instances are equivalent
        assert msp_crypto_field_model == msp_crypto_field_model2

        # Convert model instance back to dict and verify no loss of data
        msp_crypto_field_model_json2 = msp_crypto_field_model.to_dict()
        assert msp_crypto_field_model_json2 == msp_crypto_field_model_json

#-----------------------------------------------------------------------------
# Test Class for NodeOu
#-----------------------------------------------------------------------------
class TestNodeOu():

    #--------------------------------------------------------
    # Test serialization/deserialization for NodeOu
    #--------------------------------------------------------
    def test_node_ou_serialization(self):

        # Construct a json representation of a NodeOu model
        node_ou_model_json = {}
        node_ou_model_json['enabled'] = True

        # Construct a model instance of NodeOu by calling from_dict on the json representation
        node_ou_model = NodeOu.from_dict(node_ou_model_json)
        assert node_ou_model != False

        # Construct a model instance of NodeOu by calling from_dict on the json representation
        node_ou_model_dict = NodeOu.from_dict(node_ou_model_json).__dict__
        node_ou_model2 = NodeOu(**node_ou_model_dict)

        # Verify the model instances are equivalent
        assert node_ou_model == node_ou_model2

        # Convert model instance back to dict and verify no loss of data
        node_ou_model_json2 = node_ou_model.to_dict()
        assert node_ou_model_json2 == node_ou_model_json

#-----------------------------------------------------------------------------
# Test Class for NodeOuGeneral
#-----------------------------------------------------------------------------
class TestNodeOuGeneral():

    #--------------------------------------------------------
    # Test serialization/deserialization for NodeOuGeneral
    #--------------------------------------------------------
    def test_node_ou_general_serialization(self):

        # Construct a json representation of a NodeOuGeneral model
        node_ou_general_model_json = {}
        node_ou_general_model_json['enabled'] = True

        # Construct a model instance of NodeOuGeneral by calling from_dict on the json representation
        node_ou_general_model = NodeOuGeneral.from_dict(node_ou_general_model_json)
        assert node_ou_general_model != False

        # Construct a model instance of NodeOuGeneral by calling from_dict on the json representation
        node_ou_general_model_dict = NodeOuGeneral.from_dict(node_ou_general_model_json).__dict__
        node_ou_general_model2 = NodeOuGeneral(**node_ou_general_model_dict)

        # Verify the model instances are equivalent
        assert node_ou_general_model == node_ou_general_model2

        # Convert model instance back to dict and verify no loss of data
        node_ou_general_model_json2 = node_ou_general_model.to_dict()
        assert node_ou_general_model_json2 == node_ou_general_model_json


# endregion
##############################################################################
# End of Model Tests
##############################################################################
