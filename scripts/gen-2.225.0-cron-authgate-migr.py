import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    maxver = (2, 225, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = '2.225.0-cron-authgates'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        viewiden = await core.callStorm('return($lib.view.get().fork().iden)')

        opts = {'view': viewiden}
        normcron = await core.callStorm('$lib.cron.add(hour=1, query="$foo=ok")', opts=opts)

        delcron = await core.callStorm('return($lib.cron.add(hour=1, query="$foo=ok"))', opts=opts)
        core.agenda.apptdefs.pop(delcron['iden'])

        # Extra nexus event so we don't re-add our cron on startup replay
        await core.sync()

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
