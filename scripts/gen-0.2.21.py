import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

CVSSV2 = 'AV:L/AC:L/Au:M/C:P/I:C/A:N/E:ND/RL:TF/RC:ND/CDP:ND/TD:ND/CR:ND/IR:ND/AR:ND'
CVSSV3 = 'AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L/E:U/RL:O/RC:U/CR:L/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X'

async def main():

    modldir = '/tmp/v/model-0.2.21'

    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(modldir) as core:

        await core.nodes(f'[risk:vuln=(foo,) :cvss:v2="{CVSSV2}" :cvss:v3="{CVSSV3}"]')

    s_backup.backup(modldir, 'cortexes/model-0.2.21')

if __name__ == '__main__':
    asyncio.run(main())
