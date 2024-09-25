import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'model-0.2.30'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:
        await core.nodes('[inet:ipv4=192.0.0.0 inet:ipv4=192.0.0.8 inet:ipv4=192.0.0.9 inet:ipv4=192.0.0.10 inet:ipv4=192.0.0.255]')
        await core.nodes('[inet:ipv6="64:ff9b:1::" inet:ipv6="64:ff9b:1::1" inet:ipv6="64:ff9b:1::ffff" inet:ipv6="64:ff9b:1::ffff:1"]')
        await core.nodes('[inet:ipv6="2002::" inet:ipv6="2002::1" inet:ipv6="2002::fffe" inet:ipv6="2002::ffff"]')
        await core.nodes('[inet:ipv6="2001:1::1/128" inet:ipv6="2001:1::2/128"]')
        await core.nodes('[inet:ipv6="2001:3::" inet:ipv6="2001:3::1" inet:ipv6="2001:3::ffff"]')
        await core.nodes('[inet:ipv6="2001:4:112::" inet:ipv6="2001:4:112::1" inet:ipv6="2001:4:112::ffff"]')
        await core.nodes('[inet:ipv6="2001:20::" inet:ipv6="2001:20::1" inet:ipv6="2001:20::ffff"]')
        await core.nodes('[inet:ipv6="2001:30::" inet:ipv6="2001:30::1" inet:ipv6="2001:30::ffff"]')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
