"""Create safe local config and untracked admin-token secret; idempotent."""
import json
import os
from pathlib import Path
import secrets
import shutil


def main():
    template=Path('config.example.json')
    if not Path('config.json').exists():
        shutil.copyfile(template, 'config.json')
        os.chmod('config.json',0o600)
        print('Created config.json (local, not tracked)')
    else:print('Existing config.json preserved')
    local=Path('.firewall')
    local.mkdir(mode=0o700,exist_ok=True)
    token=local/'admin.token'
    if not token.exists():
        token.write_text(secrets.token_urlsafe(36)+'\n','utf-8')
        os.chmod(token,0o600)
        print('Created .firewall/admin.token (local secret, not tracked)')
    else:print('Existing .firewall/admin.token preserved')
    Path('logs').mkdir(exist_ok=True)
    print('Setup ready: start echo backend and firewall in two terminals')


if __name__=='__main__':main()
