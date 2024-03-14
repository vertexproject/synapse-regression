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

        q = '''
        $lib.model.ext.addFormProp(mat:item, _multispeed, (array, ({'type': 'velocity'})), ({}))
        '''
        await core.nodes(q)

        async def ignoreErrs(q):
            try:
                await core.nodes(q)
            except AttributeError:
                pass

        await ignoreErrs('[ transport:air:telem=(foo,) :speed=(1.23) ]')
        await ignoreErrs('[ transport:air:telem=(foo,) :airspeed=(2.34) ]')
        await ignoreErrs('[ transport:air:telem=(foo,) :verticalspeed=(3.45) ]')
        await ignoreErrs('[ transport:sea:telem=(bar,) :speed=(4.56) ]')
        await ignoreErrs('[ mat:item=(baz,) :_multispeed=((5.67), (6.78)) ]')

        await core.nodes('[ transport:sea:telem=(ok1,) :destination=(here,)]')
        await core.nodes('[ transport:sea:telem=(ok2,) :speed=10kts]')
        await core.nodes('[ mat:item=(ok3,) :_multispeed=(10kts, 20kts) ]')

        noprops = (await core.nodes('[ transport:sea:telem=(ok4,) ]'))[0]
        layr = core.getLayer()
        sode = layr._getStorNode(noprops.buid)
        sode.pop('props')
        layr.dirty[noprops.buid] = sode

        badvalu = (await core.nodes('[ transport:sea:telem=(badvalu,) ]'))[0]
        layr = core.getLayer()
        sode = layr._getStorNode(badvalu.buid)
        sode['props']['speed'] = (-1.0, 9)
        layr.dirty[badvalu.buid] = sode
        await layr._saveDirtySodes()

        await core.nodes('[ risk:mitigation=(foo,) :name="  Foo Bar  " ]')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
