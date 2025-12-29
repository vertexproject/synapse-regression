import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'model-0.2.34'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:
        nodes = await core.nodes('[ inet:email=visi+synapse@vertex.link ]')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
