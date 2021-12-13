#!/usr/bin/python3

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url


class VaultReadModule():
    argument_spec = dict(
        vault_addr=dict(type='str', required=True),
        token=dict(type='str', required=False, no_log=True),
        role_id=dict(type='str', required=False),
        secret_id=dict(type='str', no_log=True, required=False),
        secret_name=dict(type='str', required=True),
    )
    module_kwargs = {
        'supports_check_mode': True,
        'required_together': [('role_id', 'secret_id')],
        'required_one_of': [('token', 'role_id')]
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

    def _get_secret_data(self, secret_name):
        response, info = self._fetch(
            f"{self.vault_addr}/v1/secret/data/{secret_name}",
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
        secret_name = self.params['secret_name']
        result = {}

        if self.params['role_id'] and self.params['secret_id']:
            self.token = self.get_vault_token(
                self.params['role_id'], self.params['secret_id'])
        elif self.params['token']:
            self.token = self.params['token']

        result = self._get_secret_data(secret_name)

        self.exit_json(
            changed=False,
            secret=result
        )


def main():
    module = VaultReadModule()
    module()


if __name__ == '__main__':
    main()
