import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    tmpdir = '/tmp/v/model-0.2.24'
    modldir = 'cortexes/model-0.2.24'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # For CPE conversion - SYN-6716
        q = '''
        [
            // Make some nodes that are going to convert from 2.2 -> 2.3 incorrectly
            it:sec:cpe="cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~"
            it:sec:cpe="cpe:/a:1c:1c%3aenterprise:-"
            it:sec:cpe="cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~"
            it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28aazf.14%29c0"

            // Make some nodes that are valid 2.3 strings but will not set their properties correctly
            it:sec:cpe="cpe:2.3:a:x1c:1c\:enterprise:-:*:*:*:*:*:*:*"
            it:sec:cpe="cpe:2.3:a:xacurax:under_construction_\/_maintenance_mode:-:*:*:*:*:wordpress:*:*"
            it:sec:cpe="cpe:2.3:o:xzyxel:nas326_firmware:5.21\(aazf.14\)c0:*:*:*:*:*:*:*"

            it:sec:cpe="cpe:2.3:a:vendor:product\%45:version:update:edition:lng:sw_edition:target_sw:target_hw:other"
            it:sec:cpe="cpe:2.3:a:vendor2:product\%23:version:update:edition:lng:sw_edition:target_sw:target_hw:other"
        ]
        '''
        await core.nodes(q)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
