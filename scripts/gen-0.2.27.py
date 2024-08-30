import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'model-0.2.27'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:
        await core.nodes(f'[ it:dev:repo:commit=* :id=" Foo "]')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
