import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    # This script MUST be run with the pre-migration model (econ:pay:pan as a
    # type only, not a form). Run with Synapse <= 2.242.0 and with the
    # economic.py from before the econ:pay:pan form was added.
    maxver = (2, 242, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = 'model-0.2.36'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # Create an econ:pay:card with :pan set so the 0.2.36 migration has a
        # value to promote to an econ:pay:pan form node.
        await core.nodes('[ econ:pay:card=* :pan=4024007150779444 ]')

    s_backup.backup(tmpdir, modldir)

    # Remove the expanded working copy; only the compact backup should remain.
    shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    asyncio.run(main())
