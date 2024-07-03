import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    tmpdir = '/tmp/v/model-0.2.23'
    modldir = 'cortexes/model-0.2.23'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # For ipv6 scopes - SYN-5997
        await core.nodes('[ inet:ipv6="ff01::1" ]')

        # For CPE conversion - SYN-6716
        q = '''
        [
            it:sec:cpe="cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~"
            it:sec:cpe="cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~"
            it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*"
            it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0"
        ]
        '''
        await core.nodes(q)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
