import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex
import synapse.common as s_common

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    if s_version.version >= (3, 0, 0):
        mesg = f'This regression cortex MUST be generated with a 2.x.x version of Synapse, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring)

    name = '2.x.x-3.0.0-migr'
    tmpdir = f'/tmp/v/{name}'
    tmpdir2 = f'/tmp/v/{name}2'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir2) as core2:
        async with await s_cortex.Cortex.anit(tmpdir) as core:

            viewiden = await core.callStorm('return($lib.view.get().fork().iden)')
            await core.nodes('[ it:dev:str=trim1 ]', opts={'view': viewiden})

            viewiden = await core.callStorm('return($lib.view.get().fork().iden)')
            await core.nodes('[ it:dev:str=trim2 ]', opts={'view': viewiden})

            # Node edits which occur before a nexus log trim should still end up in the new nexus log
            await core.trimNexsLog()

            oldp = await core.auth.addUser('oldpass')
            await core.auth.setUserInfo(oldp.iden, 'passwd', ('old', 'tuple'))
            await core.auth.setUserInfo(oldp.iden, 'onepass', ('old', 'tuple'))

            visi = await core.auth.addUser('visi')
            await visi.setPasswd('secret')

            rusr = await core.auth.addUser('roleuser')
            role = await core.auth.addRole('somerole')
            await rusr.grant(role.iden)

            await visi.addRule((True, ('node', 'data', 'pop')))
            await visi.addRule((True, ('node', 'prop', 'set', 'inet:ipv6')))
            await visi.addRule((True, ('node', 'prop', 'set', 'inet:ipv4', 'asn')))
            await visi.addRule((True, ('node', 'prop', 'set', 'inet:ipv4', '.seen')))

            # Permissions on forms which 3.x removed, which are dropped rather
            # than rewritten onto a destination form.
            await visi.addRule((True, ('node', 'add', 'risk:availability')))
            await visi.addRule((True, ('node', 'prop', 'set', 'risk:availability', 'title')))

            await visi.addRule((True, ('macro', 'add')))
            await visi.addRule((True, ('macro', 'edit')))
            await visi.addRule((True, ('macro', 'admin')))

            await visi.addRule((True, ('auth', 'user', 'pop', 'profile')))
            await visi.addRule((True, ('storm', 'lib', 'auth', 'users', 'add')))
            await visi.addRule((True, ('storm', 'lib', 'auth', 'roles', 'add')))
            await visi.addRule((True, ('storm', 'lib', 'cortex', 'httpapi', 'set')))
            await visi.addRule((True, ('storm', 'lib', 'log', 'warning')))
            await visi.addRule((True, ('storm', 'inet', 'imap', 'connect')))

            await visi.addRule((True, ('globals', 'pop')))
            await visi.addRule((True, ('storm', 'graph', 'add')))
            await visi.addRule((True, ('cron', 'set', 'creator')))
            await visi.addRule((True, ('depr', '.newp')))

            layriden = core.getLayer().iden
            await role.addRule((True, ('node', 'data', 'pop', 'bar')), gateiden=layriden)
            await role.addRule((True, ('node', 'prop', 'set', 'inet:ipv4', 'asn')), gateiden=layriden)
            await role.addRule((True, ('cron', 'set', 'creator')))
            await role.addRule((True, ('storm', 'lib', 'auth', 'users', 'del')))
            await role.addRule((True, ('storm', 'lib', 'auth', 'roles', 'del')))
            await role.addRule((True, ('depr', '.newp')), gateiden=layriden)

            url = core2.getLocalUrl('*/layer')

            conf = {'upstream': url}
            await core.addLayer(ldef=conf)

            conf = {'mirror': url}
            await core.addLayer(ldef=conf)

            await core.nodes('''[
                inet:url="  http://vertex.link:80?test=true  "
                    +(refs)> {[ meta:event:taxonomy=whitespace.url ]}
                    <(refs)+ {[ meta:event:taxonomy=merged.one ]}
            ]''')
            await core.nodes('''[
                inet:url="http://vertex.link:80?test=true"
                    +(refs)> {[ meta:event:taxonomy=nowhitespace.url ]}
                    <(refs)+ {[ meta:event:taxonomy=merged.two ]}
            ]''')

            # both get merged refs?

            await core.nodes('[ meta:source=* :type=foo.bar ]')

            await core.nodes('''[
                it:auth:passwdhash=(foohash,)
                    :salt=0xffff
                    :passwd=foo
                    :hash:md5=$lib.crypto.hashes.md5(('foo').encode())
                    :hash:sha256=$lib.crypto.hashes.sha256(('foo').encode())
                    +#foo.tag=2020
                    +(refs)> {[ meta:source=* :name=passwdhashn1 ]}
                    <(refs)+ {[ meta:source=* :name=passwdhashn2 ]}
            ]''')

            await core.nodes('''[
                risk:attack=*
                    :target:org={[ ou:org=* :name=coolorg ]}
                    :target:host={[ it:host=* :name=coolhost ]}
                    :via:ipv4=1.2.3.4
                    :via:ipv6="7::8"
            ]''')

            await core.nodes('''[
                lang:trans=notenglish
                    :desc:en=somedesc
                    :text:en=english
            ]''')

            await core.nodes('''[
                lang:translation=(wasguid,)
                    :desc=guiddesc
                    :input=green
                    :input:lang=en
                    :output=vert
                    :output:lang=fr
                    :engine={[ it:prod:softver=* :name=covertransengine ]}
            ]''')

            # Extended model elements: a form (with a node), a form prop, a univ
            # prop, and a tag prop. These exercise the extended-model migration
            # and the extended-form path in the layer buid scan.
            await core.addForm('_cover:ext', 'int', {}, {})
            await core.addFormProp('it:dev:str', '_coverprop', ('int', {}), {})
            await core.addUnivProp('_coveruniv', ('int', {}), {})
            await core.addTagProp('coverscore', ('int', {}), {})

            await core.nodes('[ _cover:ext=42 ]')

            # Surviving node with an ndef-typed secondary prop pointing at a
            # renamed form (hash:md5 -> crypto:hash:md5).
            await core.nodes('[ ou:asset=(coverasset,) :node=(hash:md5, d41d8cd98f00b204e9800998ecf8427e) ]')

            # A deleted form (edge:refs) with ndef props; skipped during migration.
            await core.nodes('[ edge:refs=((inet:fqdn, vertex.link), (inet:fqdn, woot.com)) ]')

            # A surviving node carrying a tag, a tagprop, nodedata, an extended
            # prop, a light edge with a verb invalid for the forms, and an edge to
            # a migrated-form node (inet:ipv4 buid changes during migration).
            await core.nodes('''[ it:dev:str=coverstr
                :_coverprop=7
                +#cover.tag=2021
                +#cover.tag:coverscore=42
                +(_coveredge)> {[ it:dev:str=coverdst ]}
                +(refs)> {[ inet:ipv4=1.2.3.4 ]}
            ]''')
            await core.nodes('it:dev:str=coverstr $node.data.set(coverkey, (foo, bar))')

            # A node of a form 3.x removed, which carries the interface props a
            # taxonomy has rather than only the ones it declares itself.
            await core.nodes('[ risk:availability=cover.gone :title=coveravail ]')

            # Interval folds: 2.x properties which 3.x folds into one period.
            # Each node covers a branch of the fold. The destination types are
            # deliberately mixed, since an activity renames the interval virts
            # to began/ended and so cannot be reached by the min/max virt names.
            await core.nodes('''[
                (edu:class=(coverclass00,) :date:first=20200102 :date:last=20200304)
                (edu:class=(coverclass01,) :date:first=20200102)
                (edu:class=(coverclass02,) :date:last=20200304)
            ]''')

            # None of the folded properties are set, so no period is written.
            await core.nodes('[ edu:class=(coverclass03,) ]')

            # A duration, which 2.x counts in milliseconds and 3.x counts in
            # microseconds. Given only one end, the other comes from it. The
            # duration is written as a string, since a bare number reads as a
            # count of seconds rather than of the milliseconds it is stored in.
            await core.nodes('''[
                (ps:workhist=(coverwork00,) :started=20200102 :ended=20200304 :duration="2D")
                (ps:workhist=(coverwork01,) :ended=20200304 :duration="2D")
                (ps:workhist=(coverwork02,) :started=20200102 :duration="2D")
            ]''')

            # An instant merged with an interval the node already holds.
            await core.nodes('''[
                (sci:experiment=(coverexp00,) :time=20200115 :window=(20200101, 20200201))
                (sci:experiment=(coverexp01,) :time=20200115)
            ]''')

            # A period whose destination is a plain ival rather than an activity.
            await core.nodes('''[
                (pol:country=(covercountry00,) :founded=19910101 :dissolved=20000101)
                (pol:country=(covercountry01,) :dissolved=20000101)
            ]''')

            # An instant on a node which also migrates properties onto edges,
            # including an array whose members each become one.
            await core.nodes('''[
                risk:attack=(coverattack00,)
                    :time=20200115
                    :techniques={[ ou:technique=(covertechnique00,) :name=covertechnique ]}
            ]''')

            # Array folds on the node itself: two 2.x arrays of different types
            # merged into one, where the ipv4 members convert to the 3.x inet:ip
            # form the ipv6 members already migrate to.
            await core.nodes('''[
                crypto:x509:cert=(covercert00,)
                    :identities:ipv4s=(1.2.3.4, 5.6.7.8)
                    :identities:ipv6s=("7::8",)
            ]''')

            # A single 2.x property which became a member of a 3.x array.
            await core.nodes('[ pol:vitals=(covervitals00,) :currency=USD ]')

            # A property which became a typed reference to the node it named,
            # on a form which several 2.x forms were generalized into. The
            # label it names is migrated by a spec which renames a property.
            await core.nodes('''[
                it:dev:repo:issue:label=(coverlabeled00,)
                    :issue={[ it:dev:repo:issue=(coverissue00,) :id=coverissue ]}
                    :label={[ it:dev:repo:label=(coverlabel00,) :title=covertitle :desc=coverdesc ]}
                    :id=coverlabeled
                    :period=(20200101, 20200201)
            ]''')

            # A property which became an edge running to the node holding it,
            # rather than from it.
            await core.nodes('''[
                risk:outage=(coveroutage00,)
                    :name=coveroutage
                    :attack={[ risk:attack=(coverattack01,) ]}
            ]''')

            # A hook which turns one 2.x node into two 3.x events, and which
            # carries a file:bytes property over to both of them.
            await core.nodes('''[
                it:exec:loadlib=(coverloadlib00,)
                    :loaded=20200102
                    :unloaded=20200304
                    :path="c:/windows/system32/cover.dll"
                    :file=$file
            ]''', opts={'vars': {'file': 'e' * 64}})

            # Durations 2.x counted in milliseconds, on a form 3.x kept as it
            # was, so the values are migrated by their type alone.
            await core.nodes('''[
                it:sec:c2:config=(coverc2conf00,)
                    :connect:delay="2D"
                    :connect:interval="1D 12:00:00"
            ]''')

            # A TTL counted in seconds, which 3.x stores as a duration.
            await core.nodes('[ inet:dns:answer=(coveranswer00,) :ttl=300 ]')

            # A comp form which became an edge between the two nodes it named.
            await core.nodes('''
                $src = $lib.guid(coverseensrc)
                [ meta:source=$src :name=coverseensrc ]
                [ meta:seen=($src, (it:dev:str, coverseen)) ]
            ''')

            # Cross node array folds: the 2.x comp forms which became their own
            # 3.x form, referenced from an array on the node they named. The
            # members are collected as each layer migrates and written once the
            # layer is done, so a message and its attachments are deliberately
            # spread across the layers of a view.
            msg00 = s_common.guid('covermsg00')

            await core.nodes('[ inet:email:message=$msg :subject=coverbase ]',
                             opts={'vars': {'msg': msg00}})

            # the attachment names a file by its sha256, and the link a url, so
            # between them they cover both shapes a 2.x file:bytes value took
            opts = {'vars': {'msg': msg00, 'file': 'a' * 64, 'url': 'http://vertex.link/base'}}
            await core.nodes('''[
                (inet:email:message:attachment=($msg, $file) :name=base.txt)
                (inet:email:message:link=($msg, $url) :text=baselink)
            ]''', opts=opts)

            # a file which was never identified by a hash, which keeps its guid
            await core.nodes('[ file:bytes=$file :name=coverguidfile ]',
                             opts={'vars': {'file': f'guid:{s_common.guid("coverguidfile")}'}})

            # The message gains more members in a layer above the one holding
            # it, so that layer's fold has to union what the lower one holds.
            forkiden = await core.callStorm('return($lib.view.get().fork().iden)')

            opts = {'view': forkiden,
                    'vars': {'msg': msg00, 'file': 'b' * 64, 'url': 'http://vertex.link/fork'}}
            await core.nodes('''[
                (inet:email:message:attachment=($msg, $file) :name=fork.txt)
                (inet:email:message:link=($msg, $url) :text=forklink)
            ]''', opts=opts)

            # A url whose punycode host the current idna normalizes differently,
            # on a property the migration carries over under a new name rather
            # than renormalizing where it stands.
            msg02 = s_common.guid('covermsg02')
            opts = {'vars': {'msg': msg02, 'url': 'http://xn--aa-iuk.link/'}}
            await core.nodes('[ inet:email:message=$msg :subject=coveridna ]', opts=opts)
            await core.nodes('[ inet:email:message:link=($msg, $url) :text=idnalink ]', opts=opts)

            # A layer which belongs to a view without being its write layer, so
            # the fold has to choose the view by priority. The views used to
            # write into the lower layers are removed afterwards, leaving layr01
            # the write layer of none of them.
            layr02 = (await core.addLayer())['iden']
            layr01 = (await core.addLayer())['iden']
            layr00 = (await core.addLayer())['iden']

            view02 = (await core.addView({'layers': [layr02]}))['iden']
            view01 = (await core.addView({'layers': [layr01, layr02]}))['iden']

            msg01 = s_common.guid('covermsg01')

            opts = {'view': view02, 'vars': {'msg': msg01, 'url': 'http://vertex.link/lower'}}
            await core.nodes('[ inet:email:message=$msg :subject=coverlower ]', opts=opts)
            await core.nodes('[ inet:email:message:link=($msg, $url) :text=lowerlink ]', opts=opts)

            opts = {'view': view01, 'vars': {'msg': msg01, 'url': 'http://vertex.link/middle'}}
            await core.nodes('[ inet:email:message:link=($msg, $url) :text=middlelink ]', opts=opts)

            await core.addView({'layers': [layr00, layr01, layr02]})

            await core.delView(view01)
            await core.delView(view02)

            # CronJobs with should get 'user' populated with 'creator'
            viewiden = await core.callStorm('return($lib.view.get().fork().iden)')
            opts = {'view': viewiden}

            await core.callStorm('$lib.cron.add(hour=1, query="$foo=ok")', opts)

            # Cron with no view should get user's default view
            user1 = await core.addUser('cronuserview')
            user1iden = user1.get('iden')
            await core.callStorm('$lib.auth.users.byname(cronuserview).addRule(((true), (cron, add)))')
            await core.callStorm('$lib.auth.users.byname(cronuserview).addRule(((true), (view, read)))')
            await core.callStorm(f'$lib.auth.users.byname(cronuserview).profile."cortex:view" = {viewiden}')

            opts = {'user': user1iden, 'view': core.view.iden}
            q = '''
            $cron = $lib.cron.add(hour=1, query="$foo=userview")
            $lib.cron.move($cron.iden, (null))
            '''
            await core.callStorm(q, opts=opts)

            # Cron with no view should get cortex default view if user has no default
            user2 = await core.addUser('croncoreview')
            user2iden = user2.get('iden')
            await core.callStorm('$lib.auth.users.byname(croncoreview).addRule(((true), (cron, add)))')
            await core.callStorm('$lib.auth.users.byname(croncoreview).addRule(((true), (view, read)))')

            opts = {'user': user2iden, 'view': viewiden}
            q = '''
            $cron = $lib.cron.add(hour=1, query="$foo=coreview")
            $lib.cron.move($cron.iden, (null))
            '''
            await core.callStorm(q, opts=opts)

            # Cron with no view and deleted user gets removed
            user3 = await core.addUser('deluser')
            user3iden = user3.get('iden')
            await core.callStorm('$lib.auth.users.byname(deluser).addRule(((true), (cron, add)))')
            await core.callStorm('$lib.auth.users.byname(deluser).addRule(((true), (view, read)))')

            opts = {'user': user3iden, 'view': viewiden}
            q = '''
            $cron = $lib.cron.add(hour=1, query="$foo=noview")
            $lib.cron.move($cron.iden, (null))
            '''
            await core.callStorm(q, opts=opts)
            await core.delUser(user3iden)

            # Triggers should get 'creator' populated with 'user'
            await core.view.addTrigger({
                'cond': 'node:add',
                'form': 'it:dev:str',
                'storm': '',
                'user': visi.iden,
            })

            # Trigger queues should be cleared
            await core.view.addTrigger({
                'cond': 'node:add',
                'form': 'inet:url',
                'storm': '[ +#trig.migr ]',
                'async': True
            })
            core.view.trigtask.cancel()

            await core.nodes('[ inet:url=" http://whitespace.trigger" ]')

            nodes = await core.nodes('inet:url=" http://whitespace.trigger"')
            assert nodes[0].get('#trig.migr') is None

            providerconf00 = {
                'iden': s_common.guid('providerconf00'),
                'name': 'providerconf00',
                'client_id': 'root',
                'client_secret': 'secret',
                'scope': 'allthethings',
                'auth_uri': 'https://127.0.0.1/api/oauth/authorize',
                'token_uri': 'https://127.0.0.1/api/oauth/token',
                'redirect_uri': 'https://opticnetloc/oauth2',
                'extensions': {'pkce': True},
                'extra_auth_params': {'include_granted_scopes': 'true'},
                'ssl_verify': False
            }
            await core.nodes('''
                $lib.inet.http.oauth.v2.addProvider($providerconf)
            ''', opts={'vars': {'providerconf': providerconf00}})

    # Write a deprecated/unknown confdef into cell.yaml to be stripped during migration.
    conf = s_common.yamlload(tmpdir, 'cell.yaml') or {}
    conf['nonexist:confdef'] = 'remove-me'
    s_common.yamlsave(conf, tmpdir, 'cell.yaml')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
