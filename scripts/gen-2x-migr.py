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
            ldef = await core.addLayer(ldef=conf)

            conf = {'mirror': url}
            ldef = await core.addLayer(ldef=conf)

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
            ]''')

            # CronJobs with should get 'user' populated with 'creator'
            viewiden = await core.callStorm('return($lib.view.get().fork().iden)')
            opts = {'view': viewiden}

            normcron = await core.callStorm('$lib.cron.add(hour=1, query="$foo=ok")', opts)

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
            user3 = await core.addUser(f'deluser')
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

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
