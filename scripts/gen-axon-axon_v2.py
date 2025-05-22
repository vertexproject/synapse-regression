import shutil
import asyncio

import synapse.axon as s_axon
import synapse.tools.backup as s_backup

async def main():

    maxver = (2, 210, 0)
    if s_version.version > (2, 210, 0):
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    tmpdir = '/tmp/v/regress'
    modldir = 'cortexes/axon-axon_v2'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_axon.Axon.anit(dirn=tmpdir) as axon:

        for i in range(5):
            byts = b'foo%d' % i
            buid = await axon.put(byts)

        for i in range(3):
            byts = b'x' * (1000 + i)
            buid = await axon.put(byts)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
