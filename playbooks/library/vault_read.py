#!/usr/bin/python3

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url


class VaultReadModule():
    argument_spec = dict(
        vault_addr=dict(type='str', required=True),
        role_id=dict(type='str', required=True),
        secret_id=dict(type='str', no_log=True, required=True),
        secret_name=dict(type='str', required=True),
        mode=dict(type='str', choices=['cloud_config', 'plain'],
                  default='plain')
    )
    module_kwargs = {
        'supports_check_mode': True
    }

    def __init__(self):

        self.ansible = AnsibleModule(
            self.argument_spec,
            **self.module_kwargs)
        self.params = self.ansible.params
        self.module_name = self.ansible._name
        self.exit_json = self.ansible.exit_json
        self.fail_json = self.ansible.fail_json

    def get_vault_token(self, vault_url, role_id, secret_id):
        url = f"{vault_url}/v1/auth/approle/login"

        data = self.ansible.jsonify(dict(
            role_id=role_id,
            secret_id=secret_id
        ))
        response, info = fetch_url(
            module=self.ansible,
            url=url,
            method="POST",
            data=data
        )
        status = info['status']

        if status >= 400 and status != 404:
            self.fail_json(
                msg='Failed to login to Vault',
                status_code=status
            )
        content = ""
        if response:
            content = response.read()
        try:
            body = json.loads(content)
            token = body['auth']['client_token']
            return token
        except Exception as ex:
            self.fail_json(
                msg='Failed to process vault response',
                error=str(ex)
            )

    def __call__(self):
        vault_addr = self.params['vault_addr']
        role_id = self.params['role_id']
        secret_id = self.params['secret_id']
        secret_name = self.params['secret_name']
        mode = self.params['mode']
        result = {}

        vault_token = self.get_vault_token(
            vault_addr,
            role_id,
            secret_id
        )
        response, info = fetch_url(
            module=self.ansible,
            url=f"{vault_addr}/v1/secret/data/{secret_name}",
            method="GET",
            headers={
                'X-Vault-Token': vault_token
            }
        )
        status = info['status']
        if status >= 400:
            self.fail_json(
                msg='Failed to fetch data from vault',
                status_code=status,
                info=info
            )
        content = ""
        if response:
            content = response.read()
        try:
            data = json.loads(content)
            secret = data['data']['data']
            cloud_config = dict(auth=dict())
            if mode == 'plain':
                result = secret
            elif mode == 'cloud_config':
                auth_attrs = [
                    'auth_url', 'user_domain_name', 'username',
                    'password', 'project_name', 'project_id']
                for k, v in secret.items():
                    if k in auth_attrs:
                        cloud_config['auth'][k] = v
                    else:
                        cloud_config[k] = v
                result = cloud_config

        except Exception as ex:
            self.fail_json(
                msg="Failed to process vault response",
                error=str(ex)
            )

        self.exit_json(
            changed=False,
            secret=result
        )


def main():
    module = VaultReadModule()
    module()


if __name__ == '__main__':
    main()
