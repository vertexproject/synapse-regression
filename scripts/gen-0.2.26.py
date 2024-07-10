import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.lib.msgpack as s_msgpack

import synapse.tools.backup as s_backup

async def main():

    name = 'model-0.2.26'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        await core.nodes('[ risk:vulnerable=(foo1,) :node=(it:dev:int, 1) ]')
        await core.nodes('[ risk:vulnerable=(foo2,) :node=(it:dev:int, 1) ]')
        await core.nodes('[ risk:vulnerable=(foo3,) :node=(it:dev:int, 3) ]')

        await core.nodes("$lib.model.ext.addFormProp(inet:fqdn, _ndefs, (array, ({'type': 'ndef'})), ({}))")

        await core.nodes('[ inet:fqdn=foo.com :_ndefs=((it:dev:int, 1), (it:dev:int, 2)) ]')
        await core.nodes('[ inet:fqdn=bar.com :_ndefs=((it:dev:int, 2), (it:dev:int, 4)) ]')

        # add a bad index value for coverage
        layr = core.getLayer()
        abrv = layr.getPropAbrv('risk:vulnerable', 'node')
        layr.layrslab.put(abrv + s_msgpack.en(('newp',)), b'\x00' * 32, db=layr.byprop)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
