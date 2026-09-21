import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    if s_version.version >= (3, 0, 0):
        mesg = f'This regression cortex MUST be generated with a 2.x.x version of Synapse, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring)

    name = '3.0.0-layer-perms-migr'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # the bottom layer of the default view, which is world readable
        deflayr = core.getLayer().iden

        # a layer in a view of its own
        viewlayr = (await core.addLayer())['iden']
        viewiden = (await core.addView({'layers': (viewlayr,)}))['iden']

        # a layer which belongs to no view at all, so 3.x cannot read it
        orphlayr = (await core.addLayer())['iden']

        # a layer which is gone by the time the migration runs, leaving the
        # global rules which named it pointing at nothing
        gonelayr = (await core.addLayer())['iden']

        user = await core.auth.addUser('layruser')
        role = await core.auth.addRole('layrrole')

        # the 2.x wildcard permissions, which named the layer in the permission
        # itself and were only ever checked against the global rules
        await user.addRule((True, ('layer', 'write', viewlayr)))
        await user.addRule((False, ('layer', 'write', orphlayr)))
        await user.addRule((True, ('layer', 'write', gonelayr)))
        await user.addRule((True, ('layer', 'read', viewlayr)))
        await user.addRule((True, ('layer', 'lift', orphlayr)))

        # read permissions which named no layer, so they covered every one
        await user.addRule((True, ('layer', 'edits', 'read')))

        # permissions 3.x keeps as they are
        await user.addRule((True, ('layer', 'write')))
        await role.addRule((True, ('layer',)))

        # the layer gated form, which is what 3.x uses for write
        await user.addRule((True, ('layer', 'write')), gateiden=viewlayr)
        await role.addRule((True, ('layer', 'read')), gateiden=viewlayr)

        # 2.x made a cortex authgate but never checked it, so a rule parked
        # here did nothing until the migration moves it onto the layer
        await role.addRule((True, ('layer', 'write', orphlayr)), gateiden='cortex')

        # the all role carries layer.read on the default layer in every 2.x
        # cortex, and it is already redundant because the default view is
        # world readable
        allrole = await core.auth.getRoleByName('all')
        assert (True, ('layer', 'read')) in allrole.getRules(gateiden=deflayr)

        assert viewiden is not None

        await core.delLayer(gonelayr)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
