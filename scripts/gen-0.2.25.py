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

        cpes = [
            # CPE2.3 valid, CPE2.2 valid
            # CPE2.3 invalid, CPE2.2 invalid

            # CPE2.3 valid, CPE2.2 invalid
            'cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*',

            # CPE2.3 invalid, CPE2.2 valid
            'cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0',
            'cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~',
            'cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~',
        ]

        # For CPE conversion - SYN-6716
        q = ' '.join([f'it:sec:cpe="{cpe}"' for cpe in cpes])
        await core.nodes(f'[ {q} ]')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
