import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'itSecCpe_2_170_0'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # For CPE conversion - SYN-6716

        # CPE2.3 valid, CPE2.2 valid
        q = r'''[
            ( it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*"
                :v2_2="cpe:/a:01generator:pireospay:-::~~~prestashop~~"
            )

            ( it:sec:cpe="cpe:2.3:a:abine:donottrackme_-_mobile_privacy:1.1.8:*:*:*:*:android:*:*"
                :v2_2="cpe:/a:abine:donottrackme_-_mobile_privacy:1.1.8::~~~android~~"
            )

            +#test.cpe.23valid
            +#test.cpe.22valid
        ]'''
        await core.callStorm(q)

        # CPE2.3 invalid, CPE2.2 invalid
        q = r'''[
            ( it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*"
                :v2_2="cpe:/a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2"
            )

            ( it:sec:cpe="cpe:2.3:a:openbsd:openssh:7.4\r\n:*:*:*:*:*:*:*"
                :v2_2="cpe:/a:openbsd:openssh:7.4\r\n"
            )

            +#test.cpe.23invalid
            +#test.cpe.22invalid
        ]'''
        await core.callStorm(q)

        # CPE2.3 valid, CPE2.2 invalid
        q = r'''[
            it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*"
            it:sec:cpe="cpe:2.3:a:abinitio:control\\>center:-:*:*:*:*:*:*:*"
            it:sec:cpe="cpe:/o:zyxel:nas542_firmware:5.21\%28aazf.15\%29co"

            +#test.cpe.23valid
            +#test.cpe.22invalid
        ]'''
        await core.callStorm(q)

        # CPE2.3 invalid, CPE2.2 valid
        q = r'''[
            it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0"
            it:sec:cpe="cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~"
            it:sec:cpe="cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~"
            ( it:sec:cpe="cpe:2.3:h:d\\-link:dir\\-850l:*:*:*:*:*:*:*:*"
                :v2_2="cpe:/h:d-link:dir-850l"
            )

            +#test.cpe.23invalid
            +#test.cpe.22valid
        ]'''
        await core.callStorm(q)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
