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
            ( ou:conference=(SleuthCon,) :name=SleuthCon )
            ( ou:conference=(Defconf,) :name=Defcon )
            ( ou:conference=(REcon,) :name="REcon 2024  Conference  " )
            ( ou:conference=(Blackhat,) :name=Blackhat )
            ( ou:conference=(SummerCon,) :name=SummerCon )
        ]
        '''
        await core.nodes(q)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
