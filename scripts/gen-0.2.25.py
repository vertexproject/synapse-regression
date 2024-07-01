import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'model-0.2.25'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        q = '''
        [
            ( ou:conference=(sleuthcon,) :name=SleuthCon :names+="SleuthCon 2024")
            ( ou:conference=(defcon,) :name=Defcon :names+="Defcon   2024")
            ( ou:conference=(recon,) :name=REcon :names+="REcon 2024  Conference  " )

            ( ou:position=(potus,)
                :title = 'President of the    United States'
            )

            ( ou:position=(vpotus,)
                :title = ' Vice  President  of  the  United States   '
            )
        ]
        '''
        await core.nodes(q)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
