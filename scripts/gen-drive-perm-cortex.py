import asyncio
import shutil

import synapse.common as s_common
import synapse.cortex as s_cortex

import synapse.lib.cell as s_cell
import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():
    maxver = (2, 213, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = 'drive-perm-migr'
    tmpdir = f'/tmp/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:
        ldog = await core.auth.addRole('littledog')
        bdog = await core.auth.addRole('bigdog')

        louis = await core.auth.addUser('lewis')
        tim = await core.auth.addUser('tim')
        mj = await core.auth.addUser('mj')

        await core.addUserRole(tim.iden, ldog.iden)
        await core.addUserRole(louis.iden, bdog.iden)

        name = 'driveitemdefaultperms'
        info = {
            'name': name,
            'iden': s_common.guid((name,)),
            'version': (0, 1, 0)
        }
        await core.addDriveItem(info)

        name = 'permfolder'
        info = {
            'name': name,
            'iden': s_common.guid((name,)),
            'version': (1, 0, 0),
            'perm': {
                'users': {
                    tim.iden: s_cell.PERM_ADMIN
                },
                'roles': {}
            }
        }
        await core.addDriveItem(info)

        name = 'driveitemwithperms'
        info = {
            'name': name,
            'iden': s_common.guid((name,)),
            'perm': {
                'users': {
                    mj.iden: s_cell.PERM_ADMIN,
                },
                'roles': {
                    ldog.iden: s_cell.PERM_READ,
                    bdog.iden: s_cell.PERM_EDIT,
                },
                'default': s_cell.PERM_DENY
            },
            'version': (0, 1, 0)
        }
        await core.addDriveItem(info, path='permfolder')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
