# generate an 0.1.x cortex
'''
Generate an 0.1.x cortex for testing migration to 0.2.x
'''
import os
import json
import shutil
import asyncio
import hashlib

import synapse.common as s_common
import synapse.cortex as s_cortex
import synapse.lib.module as s_module
import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

assert s_version.version == (0, 1, 51)

DESTPATH_CORTEX = 'cortexes/0.1.51-migr'
DESTPATH_ASSETS = 'assets/0.1.51-migr'

class MigrMod(s_module.CoreModule):

    def getModelDefs(self):
        name = 'migr'

        ctors = ()

        types = (
            ('migr:test', ('int', {}), {}),
        )

        forms = (
            ('migr:test', {}, (
                ('bar', ('str', {'lower': True}), {}),
            )),
        )

        modldef = (name, {
            'ctors': ctors,
            'forms': forms,
            'types': types,
        })
        return (modldef, )

async def main():

    with s_common.getTempDir() as dirn:
        path = os.path.join(dirn, 'cortex')
        conf = {
            'dedicated': True,
        }

        podes = []
        nodedata = []  # [ ndef, [item1, item2, ... ]
        async with await s_cortex.Cortex.anit(path, conf=conf) as core:
            async with core.getLocalProxy() as proxy:
                # load modules
                await core.loadCoreModule('020migr-01x.MigrMod')
                await core.loadCoreModule('synapse.tests.utils.TestModule')

                # create forked view with some nodes
                view2 = await core.view.fork()
                await view2.nodes('[test:int=10]')

                # add roles and permissions
                role1 = await core.auth.addRole('ninjas')
                role2 = await core.auth.addRole('cowboys')
                role3 = await core.auth.addRole('friends')

                await proxy.addAuthRule('friends', (True, ('view', 'read')), iden=view2.iden)
                await proxy.addAuthRule('friends', (True, ('node:add',)), iden=view2.layers[0].iden)
                await proxy.addAuthRule('friends', (True, ('prop:set',)), iden=view2.layers[0].iden)

                await role1.addRule((True, ('baz', 'faz')))

                # create fred who can add a tag and triggers, and read the forked view
                fred = await core.auth.addUser('fred')

                await fred.grant('ninjas')

                await proxy.addAuthRule('fred', (True, ('view', 'read')), iden=view2.iden)

                await fred.addRule((True, ('tag:add', 'trgtag')))
                await fred.addRule((True, ('trigger', 'add')))
                await fred.addRule((True, ('trigger', 'get')))
                await fred.addRule((True, ('storm', 'queue', 'get')))
                await fred.addRule((True, ('storm', 'queue', 'add')))

                # create bobo who can write to the layer but doesn't have the trigger rules
                bobo = await core.auth.addUser('bobo')
                await bobo.setPasswd('secret')

                await bobo.grant('friends')

                await bobo.addRule((True, ('tag:add', 'bobotag')))
                await bobo.addRule((True, ('storm', 'queue', 'get')))
                await bobo.addRule((True, ('storm', 'queue', 'put')))
                await bobo.addRule((True, ('storm', 'queue', 'boboq')))

                # add triggers
                await core.addTrigger('node:add', '[ +#trgtag ]', info={'form': 'inet:ipv4'}, user=fred)
                await core.addTrigger('tag:add', '[ inet:ipv4=5.5.5.5 ]', info={'tag': 'foo.*.baz'})

                # add queues
                rule = (True, ('storm', 'queue', 'fredq', 'get'))
                await proxy.addAuthRule('friends', rule)

                await core.eval('queue.add rootq').list()
                await core.eval('queue.add fredq', user=fred).list()
                await core.eval('queue.add boboq').list()
                assert len(await core.getCoreQueues()) == 3

                # extend the data model
                await core.addFormProp('inet:ipv4', '_rdxp', ('int', {}), {})
                await core.addFormProp('inet:ipv4', '_rdxpz', ('int', {}), {})
                await core.addUnivProp('_rdxu', ('str', {'lower': True}), {})
                await core.addUnivProp('_rdxuz', ('str', {'lower': True}), {})
                await core.addTagProp('score', ('int', {}), {})
                await core.addTagProp('nah', ('int', {}), {})

                # module forms
                scmd = '[ migr:test=22 :bar=spam ]'
                await core.nodes(scmd)

                # crypto
                scmd = '[ crypto:currency:client=(1.2.3.4, (btc, 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2)) ]'
                await core.nodes(scmd)

                scmd = (
                    f'[ econ:acct:payment="*"'
                    f' :from:coinaddr=(btc, 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2)'
                    f' :to:coinaddr=(btc, 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2)]'
                )
                await core.nodes(scmd)

                # geospace
                scmd = '[ geo:place="*" :latlong=(-30.0,20.22) +#foo.bar.baz.spam] $node.data.set(cat, dog)'
                await core.nodes(scmd)

                scmd = (
                    f'[ geo:nloc=('
                    f'("inet:wifi:ap", ("BHOT-2019", "d8:38:fc:13:87:5c")), '
                    f'("43.41483078", "39.94891608"), '
                    f'"2019"'
                    f') ]'
                )
                await core.nodes(scmd)

                # dns
                scmd = '[ inet:dns:a=(woot.com, 1.2.3.4) inet:dns:a=(vertex.link, 1.2.3.4) ]'
                await core.nodes(scmd)

                # inet
                scmd = (
                    f'[ inet:ipv4=1.2.3.4 :latlong=(-30.0, 20.22) .seen=("2005", "2006")'
                    f' :_rdxp=7 ._rdxuz=woot +#foo=("2012", "2013")]'
                )
                await core.nodes(scmd)

                scmd = (
                    f'[ inet:ipv4=5.6.7.8 :loc=nl :_rdxpz=7 +#foo:nah=42 ]'
                    f' $node.data.set(car, cool)'
                )
                await core.nodes(scmd)

                scmd = (
                    f'inet:ipv4=5.6.7.8 $node.data.set(cat, lion)'
                )
                await core.nodes(scmd)

                # infotech
                scmd = f'[ it:prod:softver=$lib.guid() :vers="3.4.45" ]'
                await core.nodes(scmd)

                # files
                bytstr = b'foobar'
                scmd = f'$buf={bytstr} [ file:bytes=$buf.encode() ._rdxu=22 +#faz.baz +#foo.bar:score=9 ]'
                await core.nodes(scmd)

                sha256 = hashlib.sha256(b'spambam').hexdigest()
                scmd = f'[ file:bytes={sha256} :mime=x509 :size=375] $node.data.set(car, cat)'
                await core.nodes(scmd)

                # base
                scmd = '[ edge:has=((inet:ipv4, 1.2.3.4), (inet:ipv4, 5.6.7.8)) ]'
                await core.nodes(scmd)

                guid = s_common.guid()
                scmd = f'[ meta:source={guid} :name=foosrc :type=osint ]'
                await core.nodes(scmd)

                scmd = f'[ meta:seen=({guid}, (inet:ipv4, 1.2.3.4))] $node.data.set(jazz, bam)'
                await core.nodes(scmd)

                # verify that triggers were activated
                assert 1 == len(await core.nodes('inet:ipv4=5.5.5.5'))
                assert 3 == len(await core.nodes('inet:ipv4#trgtag'))

                # delete source test node
                await core.nodes('meta:source:name=test | delnode')

                # pack up all the nodes
                for node in await core.nodes('.created'):
                    podes.append(node.pack(dorepr=True))
                    nodedata.append((node.ndef, [nd async for nd in node.iterData()]))

        # only run from checkout dir
        shutil.rmtree(DESTPATH_CORTEX, ignore_errors=True)
        shutil.rmtree(DESTPATH_ASSETS, ignore_errors=True)

        s_backup.backup(path, DESTPATH_CORTEX)

        if not os.path.exists(DESTPATH_ASSETS):
            s_common.gendir(DESTPATH_ASSETS)

        with open(os.path.join(DESTPATH_ASSETS, 'podes.json'), 'w') as f:
            f.write(json.dumps(podes, indent=4))

        with open(os.path.join(DESTPATH_ASSETS, 'nodedata.json'), 'w') as f:
            f.write(json.dumps(nodedata, indent=2))

if __name__ == '__main__':
    asyncio.run(main())