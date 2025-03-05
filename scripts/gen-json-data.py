import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    maxver = (2, 202, 0)
    if s_version.version > (2, 202, 0):
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = 'json-data'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:
        opts = {
            'vars': {
                'data': {
                    1: 'foo',
                    'foo': '😀\ud83d\ude47',
                }
            }
        }
        nodes = await core.nodes('[ it:log:event=* :data=$data ]', opts=opts)
        assert len(nodes) == 1

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
