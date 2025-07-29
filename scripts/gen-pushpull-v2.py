import shutil
import asyncio

import synapse.cortex as s_cortex
import synapse.tools.backup as s_backup

import synapse.lib.version as s_version

async def main():

    maxver = (2, 217, 0)
    if s_version.version > (2, 217, 0):
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    tmpdir = '/tmp/v/regress'
    modldir = 'cortexes/pushpull-v2'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

            await core.auth.rootuser.setPasswd('secret')
            host, port = await core.dmon.listen('tcp://127.0.0.1:0/')

            view0, layr0 = await core.callStorm('$view = $lib.view.get().fork() return(($view.iden, $view.layers.0.iden))')
            view1, layr1 = await core.callStorm('$view = $lib.view.get().fork() return(($view.iden, $view.layers.0.iden))')
            view2, layr2 = await core.callStorm('$view = $lib.view.get().fork() return(($view.iden, $view.layers.0.iden))')
            opts = {'vars': {
                'view0': view0,
                'view1': view1,
                'view2': view2,
                'layr0': layr0,
                'layr1': layr1,
                'layr2': layr2,
            }}

            # view0 -push-> view1 <-pull- view2
            await core.callStorm(f'$lib.layer.get($layr0).addPush("tcp://root:secret@127.0.0.1:{port}/*/layer/{layr1}")', opts=opts)
            await core.callStorm(f'$lib.layer.get($layr2).addPull("tcp://root:secret@127.0.0.1:{port}/*/layer/{layr1}")', opts=opts)

            await core.nodes('[ ps:contact=* ]', opts={'view': view0})

            # wait for first write so we can get the correct offset
            await core.layers.get(layr2).waitEditOffs(0, timeout=3)
            offs = await core.layers.get(layr2).getEditOffs()

            await core.nodes('[ ps:contact=* ]', opts={'view': view0})
            await core.nodes('[ ps:contact=* ]', opts={'view': view0})
            await core.layers.get(layr2).waitEditOffs(offs + 10, timeout=3)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
