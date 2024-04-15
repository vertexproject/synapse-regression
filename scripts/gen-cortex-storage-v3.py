import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'cortex-storage-v3'

    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:
        view = await core.callStorm('return($lib.view.get().fork().iden)')
        opts = {'view': view}

        await core.nodes('[ ou:org=* ]', opts=opts)
        await core.nodes('$lib.view.get().set(nomerge, $lib.true)', opts=opts)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
