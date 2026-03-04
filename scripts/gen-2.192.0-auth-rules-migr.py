import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    maxver = (2, 192, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = '2.192.0-auth-rules-migr'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # user with lgeacy profile perms
        user = await core.auth.addUser('visi')
        await core.addUserRule(user.iden, (True, ('auth', 'user', 'get', 'profile', 'fullname')))
        await core.addUserRule(user.iden, (True, ('auth', 'user', 'set', 'profile', 'fullname')))
        await core.addUserRule(user.iden, (True, ('auth', 'user', 'pop', 'profile', 'fullname')))

        # role with legacy profile perms
        role = await core.auth.addRole('visi-role')
        await core.addRoleRule(role.iden, (False, ('auth', 'user', 'del', 'profile', 'nickname')))

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
