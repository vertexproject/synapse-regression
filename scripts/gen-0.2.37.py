import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version
import synapse.lib.modelrev as s_modelrev

import synapse.tools.backup as s_backup

async def main():

    # This script MUST be run with the pre-migration model, where the
    # econ:bank:swift:bic regex is anchored only at the start and therefore
    # accepts trailing characters after a valid BIC. Run with Synapse <= 2.250.0.
    maxver = (2, 250, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    # The version check alone does not catch a 2.250.0 checkout which already
    # carries the model change, so check the model revision directly.
    if s_modelrev.maxvers >= (0, 2, 37):
        mesg = f'This regression cortex MUST be generated before model revision 0.2.37, not {s_modelrev.maxvers}.'
        raise s_exc.BadVersion(mesg=mesg, curv=str(s_modelrev.maxvers))

    name = 'model-0.2.37'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # An invalid BIC carrying properties, a tag, nodedata and an edge, so the
        # migration has a fully populated node to quarantine into the queue.
        await core.nodes('''[
            econ:bank:swift:bic=DEUTDEFFXXXXX
                :business={ gen.ou.org acme }
                :office=*
                +#some.tag
                +(refs)> {[ inet:fqdn=vertex.link ]}
        ]''')
        await core.nodes('econ:bank:swift:bic=DEUTDEFFXXXXX $node.data.set(woot, hehe)')

        # A bare invalid BIC.
        await core.nodes('[ econ:bank:swift:bic=TRWIBEB1XXXjunk ]')

        # A valid 11 character BIC which the migration must leave alone.
        await core.nodes('[ econ:bank:swift:bic=DEUTDEFFXXX :business={ gen.ou.org vertex } ]')

        # An invalid BIC in a forked view, so the migration is exercised across
        # more than one layer.
        fork = await core.callStorm('''
            $view = $lib.view.get().fork()
            $view.set(name, fork00)
            return($view.iden)
        ''')
        await core.nodes('[ econ:bank:swift:bic=BNPAFRPPXXXjunk ]', opts={'view': fork})

    s_backup.backup(tmpdir, modldir)

    # Remove the expanded working copy; only the compact backup should remain.
    shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    asyncio.run(main())
