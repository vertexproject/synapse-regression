import shutil
import asyncio

from unittest import mock

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.time as s_time
import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

def now():
    return s_time.parse('20260319')

async def main():

    maxver = (2, 235, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = 'model-0.2.35'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # Add extended model forms that have secondary props of the forms we're updating
        await core.addForm('_ext:model:form', 'str', {}, {})
        await core.addFormProp('_ext:model:form', 'client', ('inet:client', {}), {})
        await core.addFormProp('_ext:model:form', 'clients', ('array', {'type': 'inet:client'}), {})
        await core.addFormProp('_ext:model:form', 'server', ('inet:server', {}), {})
        await core.addFormProp('_ext:model:form', 'servers', ('array', {'type': 'inet:server'}), {})
        await core.addFormProp('_ext:model:form', 'url', ('inet:url', {}), {})
        await core.addFormProp('_ext:model:form', 'urls', ('array', {'type': 'inet:url'}), {})
        await core.addFormProp('_ext:model:form', 'urlfile', ('inet:urlfile', {}), {})
        await core.addFormProp('_ext:model:form', 'urlfiles', ('array', {'type': 'inet:urlfile'}), {})
        await core.addFormProp('_ext:model:form', 'ja3:sample', ('inet:tls:ja3:sample', {}), {})
        await core.addFormProp('_ext:model:form', 'ja3:samples', ('array', {'type': 'inet:tls:ja3:sample'}), {})
        await core.addFormProp('_ext:model:form', 'ja3s:sample', ('inet:tls:ja3s:sample', {}), {})
        await core.addFormProp('_ext:model:form', 'ja3s:samples', ('array', {'type': 'inet:tls:ja3s:sample'}), {})
        await core.addFormProp('inet:client', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:server', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:url', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:tls:ja3:sample', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:tls:ja3s:sample', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:urlfile', '_valid', ('bool', {}), {})
        await core.addTagProp('score', ('int', {}), {})

        md5_00 = '86d3f3a95c324c9479bd8986968f4327'
        md5_01 = '252ce2dd876a03ea51cc9e11517dd4ed'
        sha256 = 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4'

        fork00 = await core.callStorm('return($lib.view.get().fork(name=fork00).iden)')
        infork00 = {'view': fork00, 'vars': {'md5_00': md5_00, 'md5_01': md5_01, 'sha256': sha256}}
        print(f'{fork00=}')

        fork01 = await core.callStorm('return($lib.view.get().fork(name=fork01).iden)', opts=infork00)
        infork01 = {'view': fork01, 'vars': {'md5_00': md5_00, 'md5_01': md5_01, 'sha256': sha256}}
        print(f'{fork01=}')

        # invalid inet:client
        # invalid inet:server
        # invalid inet:url
        q = r'''
            function adorn(n) {
                yield $n
                [
                    .seen = (2019, 2022)

                    +#test.foo00 = (2019, 2022)
                    +#test.foo01 = (2020, 2021)
                    +#test.foo02
                    +#test.foo03 = (2020, 2026)
                    +#test.invalid
                    +#test.tagprop:score = 0
                    +#test.same:score = 10

                    <(seen)+ {[ meta:source=(regression, 0.2.35, invalid) :type=synapse.regression ]}
                ]

                $node.data.set('addr', 'invalid')
                $node.data.set('same', 'same')
                $node.data.set('only', 'value')
                return()
            }

            $client = {[ inet:client="tcp://::1" :_valid=(false) ] $adorn($node) }
            $server = {[ inet:server="tcp://::2" :_valid=(false) ] $adorn($node) }
            $url = {[ inet:url="http://::3" :_valid=(false) ] $adorn($node) }

            // linked comp types
            $ja3 = {[ inet:tls:ja3:sample=($client, $md5_00) :_valid=(false) ] $adorn($node) }
            $ja3s = {[ inet:tls:ja3s:sample=($server, $md5_00) :_valid=(false) ] $adorn($node) }
            $urlfile = {[ inet:urlfile=($url, `sha256:{$sha256}`) :_valid=(false) ] $adorn($node) }

            [
                // linked props
                ( inet:flow=(regression, 0.2.35, client00, invalid) :src=$client )
                ( inet:flow=(regression, 0.2.35, server00, invalid) :dst=$server )
                ( risk:vuln=(regression, 0.2.35, url00, invalid) :cve:url=$url )

                // Second degree refs and extended model
                ( _ext:model:form=invalid
                    :client=$client
                    :clients=($client,)
                    :server=$server
                    :servers=($server,)
                    :url=$url
                    :urls=($url,)
                    :urlfile=$urlfile
                    :urlfiles=($urlfile,)
                    :ja3:sample=$ja3
                    :ja3:samples=($ja3,)
                    :ja3s:sample=$ja3s
                    :ja3s:samples=($ja3s,)
                )
            ]

            $adorn($node)
        '''
        with mock.patch('synapse.common.now', now):
            await core.callStorm(q, opts=infork00)

        # valid inet:client
        # valid inet:server
        # valid inet:url
        q = r'''
            function adorn(n) {
                yield $n
                [
                    .seen = (2020, 2021)

                    +#test.foo00 = (2020, 2021)
                    +#test.foo01 = (2019, 2022)
                    +#test.foo02 = (2020, 2026)
                    +#test.foo03
                    +#test.valid
                    +#test.tagprop:score = 1
                    +#test.same:score = 10

                    <(seen)+ {[ meta:source=(regression, 0.2.35, valid) :type=synapse.regression ]}
                ]
                $node.data.set('addr', 'valid')
                $node.data.set('same', 'same')
                return()
            }

            $client00 = {[ inet:client="tcp://[::1]" :_valid=(true) ] $adorn($node) }
            $client01 = {[ inet:client="tcp://[::1]:80" :_valid=(true) ] $adorn($node) }

            $server00 = {[ inet:server="tcp://[::2]" :_valid=(true) ] $adorn($node) }
            $server01 = {[ inet:server="tcp://[::2]:80" :_valid=(true) ] $adorn($node) }

            $url00 = {[ inet:url="http://[::3]" :_valid=(true) ] $adorn($node) }
            $url01 = {[ inet:url="http://[::3]:80" :_valid=(true) ] $adorn($node) }

            // linked comp types
            $ja300 = {[ inet:tls:ja3:sample=("tcp://[::1]", $md5_00) :_valid=(true) ] $adorn($node) }
            $ja301 = {[ inet:tls:ja3:sample=("tcp://[::1]:80", $md5_00) :_valid=(true) ] $adorn($node) }
            $ja3s00 = {[ inet:tls:ja3s:sample=("tcp://[::2]", $md5_00) :_valid=(true) ] $adorn($node) }
            $ja3s01 = {[ inet:tls:ja3s:sample=("tcp://[::2]:80", $md5_00) :_valid=(true) ] $adorn($node) }
            $urlfile00 = {[ inet:urlfile=("http://[::3]", `sha256:{$sha256}`) :_valid=(true) ] $adorn($node) }
            $urlfile01 = {[ inet:urlfile=("http://[::3]:80", `sha256:{$sha256}`) :_valid=(true) ] $adorn($node) }

            [

                // linked props
                ( inet:flow=(regression, 0.2.35, client00, valid) :src=$client00 )
                ( inet:flow=(regression, 0.2.35, client01, valid) :src=$client01 )

                ( inet:flow=(regression, 0.2.35, server00, valid) :dst=$server00 )
                ( inet:flow=(regression, 0.2.35, server01, valid) :dst=$server01 )

                ( risk:vuln=(regression, 0.2.35, url00, valid) :cve:url=$url00 )
                ( risk:vuln=(regression, 0.2.35, url01, valid) :cve:url=$url01 )

                // Second degree refs and extended model
                ( _ext:model:form=valid
                    :client=$client00
                    :clients=($client00, $client01)
                    :server=$server00
                    :servers=($server00, $server01)
                    :url=$url00
                    :urls=($url00, $url01)
                    :urlfile=$urlfile00
                    :urlfiles=($urlfile00, $urlfile01)
                    :ja3:sample=$ja300
                    :ja3:samples=($ja300, $ja301)
                    :ja3s:sample=$ja3s00
                    :ja3s:samples=($ja3s00, $ja3s01)
                )
            ]

            $adorn($node)
        '''
        with mock.patch('synapse.common.now', now):
            await core.callStorm(q, opts=infork00)

        q = r'''
            $_ = { inet:client="tcp://::1" [ :port=80 .seen=(2019, 2020) ] }
            $_ = { inet:server="tcp://::2" [ :port=80 ] }
        '''
        with mock.patch('synapse.common.now', now):
            await core.callStorm(q, opts=infork01)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
