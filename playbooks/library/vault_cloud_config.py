#!/usr/bin/python3

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.urls import fetch_url

try:
    import openstack
    HAS_OPENSTACK = True
except ImportError:
    HAS_OPENSTACK = False


class VaultCloudConfigModule():
    argument_spec = dict(
        vault_addr=dict(type='str', required=True),
        vault_role_id=dict(type='str'),
        vault_secret_id=dict(type='str', no_log=True),
        vault_token=dict(type='str', no_log=True),
        cloud_secret_path=dict(type='str'),
        project_name=dict(type='str'),
        mode=dict(type='str', defualt='config',
                  chocies=['config', 'token'])
    )
    module_kwargs = {
        'supports_check_mode': True,
        'required_together': [('vault_role_id', 'vault_secret_id')],
        'required_one_of': [('vault_token', 'vault_role_id')]
    }

    def __init__(self):

        self.ansible = AnsibleModule(
            self.argument_spec,
            **self.module_kwargs)
        self.params = self.ansible.params
        self.module_name = self.ansible._name
        self.exit_json = self.ansible.exit_json
        self.fail_json = self.ansible.fail_json
        self.vault_addr = None
        self.token = None

    def _fetch(self, url, method, **kwargs):
        response, info = fetch_url(
            module=self.ansible,
            url=url,
            method=method,
            **kwargs
        )
        status = info['status']

        if status >= 400 and status != 404:
            self.fail_json(
                msg=f'Failed to fetch {url}',
                status_code=status
            )
        content = ""
        if response:
            content = response.read()
        return (content, status)

    def _get_secret_data(self, secret_path):
        response, info = self._fetch(
            f"{self.vault_addr}/v1/secret/data/{secret_path}",
            "GET",
            headers={
                'X-Vault-Token': self.token
            }
        )
        return json.loads(response)['data']['data']

    def get_vault_token(self, role_id, secret_id):
        url = f"{self.vault_addr}/v1/auth/approle/login"

        data = self.ansible.jsonify(dict(
            role_id=role_id,
            secret_id=secret_id
        ))
        response, into = self._fetch(
            url, "POST", data=data
        )
        try:
            body = json.loads(response)
            token = body['auth']['client_token']
            return token
        except Exception as ex:
            self.fail_json(
                msg='Failed to process vault response',
                error=str(ex)
            )

    def __call__(self):
        self.vault_addr = self.params['vault_addr']
        cloud_secret_path = self.params['cloud_secret_path']
        project_name = self.params['project_name']

        result = {}

        if self.params['vault_role_id'] and self.params['vault_secret_id']:
            self.token = self.get_vault_token(
                self.params['vault_role_id'], self.params['vault_secret_id'])
        elif self.params['vault_token']:
            self.token = self.params['vault_token']

        cloud_data = self._get_secret_data(cloud_secret_path)
        user_secret_name = cloud_data.pop('user_secret_name', '')
        if user_secret_name:
            # user_secret_name is found in cloud_data. Resolve it's value
            cloud_data.update(self._get_secret_data(user_secret_name))

        try:
            cloud_config = dict(auth=dict())
            # this attrs go under 'auth'
            auth_attrs = [
                'auth_url',
                'user_domain_name', 'user_domain_id',
                'username', 'user_id', 'password',
                'project_name', 'project_id',
                'project_domain_id', 'project_domain_name',
                'domain_id', 'domain_name']
            for k, v in cloud_data.items():
                if k in auth_attrs:
                    cloud_config['auth'][k] = v
                else:
                    cloud_config[k] = v
            if project_name:
                cloud_config['auth'].pop('project_name', None)
                cloud_config['auth'].pop('project_id', None)
                cloud_config['auth']['project_name'] = project_name

            result = cloud_config

            if self.params['mode'] == 'token':
                if not HAS_OPENSTACK:
                    self.fail_json(msg=missing_required_lib('openstacksdk'))

                try:
                    conn = openstack.connect(**cloud_config)
                    token = conn.auth_token
                    new_auth = dict()
                    result['auth_type'] = 'token'
                    new_auth['auth_url'] = conn.config._auth.auth_url
                    new_auth['project_name'] = \
                        cloud_config['auth']['project_name']
                    new_auth['token'] = token
                    result['auth'] = new_auth
                except openstack.exceptions.SDKException as e:
                    self.fail_json(
                        msg='Failure connecting to the cloud',
                        error=str(e)
                    )

        except Exception as ex:
            self.fail_json(
                msg="Failed to process vault response",
                error=str(ex)
            )

        self.exit_json(
            changed=False,
            token=token,
            config=result
        )


def main():
    module = VaultCloudConfigModule()
    module()


if __name__ == '__main__':
    main()
