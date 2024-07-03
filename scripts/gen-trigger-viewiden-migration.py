import shutil
import asyncio

import synapse.common as s_common
import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    tmpdir = '/tmp/v/regress'
    modldir = 'cortexes/trigger-viewiden-migration'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        for ii in range(5):
            ldef = await core.addLayer({})
            layriden = ldef.get('iden')

            vdef = {
                'layers': [layriden]
            }
            vdef = await core.addView(vdef)

            tdef = {
                'iden': s_common.guid(),
                'view': s_common.guid(),
                'cond': 'node:add',
                'storm': 'test:int=4',
                'form': 'test:int',
            }
            view = core.reqView(vdef.get('iden'))
            tdef = await view.addTrigger(tdef)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
