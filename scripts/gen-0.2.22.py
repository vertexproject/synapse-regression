import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    tmpdir = '/tmp/v/model-0.2.22'
    modldir = 'cortexes/model-0.2.22'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # 100.64.0.0/10 goes from 100.64.0.0 to 100.127.255.255. Get a good chunk at the beginning
        # and the broadcast address for bookend testing.
        await core.nodes('[ inet:ipv4=100.64.0.0/24 ]')
        await core.nodes('[ inet:ipv4=100.127.255.255 ]')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
