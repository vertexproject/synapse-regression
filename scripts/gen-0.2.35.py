import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

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

        # Add extended model forms that have secondary props of
        await core.addForm('_ext:model:form', 'str', {}, {})
        await core.addFormProp('_ext:model:form', 'client', ('inet:client', {}), {})
        await core.addFormProp('_ext:model:form', 'server', ('inet:server', {}), {})
        await core.addFormProp('_ext:model:form', 'url', ('inet:url', {}), {})
        await core.addFormProp('_ext:model:form', 'ja3:sample', ('inet:tls:ja3:sample', {}), {})
        await core.addFormProp('_ext:model:form', 'ja3s:sample', ('inet:tls:ja3s:sample', {}), {})
        await core.addFormProp('inet:client', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:server', '_valid', ('bool', {}), {})
        await core.addFormProp('inet:url', '_valid', ('bool', {}), {})
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

        fork02 = await core.callStorm('return($lib.view.get().fork(name=fork02).iden)', opts=infork01)
        infork02 = {'view': fork02, 'vars': {'md5_00': md5_00, 'md5_01': md5_01, 'sha256': sha256}}
        print(f'{fork02=}')

        fork03 = await core.callStorm('return($lib.view.get().fork(name=fork03).iden)')
        infork03 = {'view': fork03, 'vars': {'md5_00': md5_00, 'md5_01': md5_01, 'sha256': sha256}}
        print(f'{fork03=}')

        layer00 = await core.callStorm('return($lib.view.get().layers.0.iden)')
        layer03 = await core.callStorm('return($lib.view.get().layers.0.iden)', opts=infork03)

        # We need layer03 to be processed first so the node in layer00 will be marked as migratable and the same node in
        # layer00 will be marked as remove.
#        assert layer03 < layer00, f'{layer00=}, {layer03=}'

        # invalid inet:client
        # invalid inet:server
        # invalid inet:url
        q = r'''[
            ( inet:client="tcp://[::1]" :_valid=(false) )
            ( inet:server="tcp://[::2]" :_valid=(false) )
            ( inet:url="http://[::3]" :_valid=(false) )

            // linked props
            ( inet:flow=(regression 0.2.35, client00, invalid) :src="tcp://[::1]" )
            ( inet:flow=(regression 0.2.35, server00, invalid) :dst="tcp://[::2]" )
            ( risk:vuln=(regression, 0.2.35, url00, invalid) :cve:url="http://[::3]" )

            // linked comp types
            ( inet:tls:ja3:sample=("tcp://[::1]", $md5_00) )
            ( inet:tls:ja3s:sample=("tcp://[::2]", $md5_00) )
            ( inet:urlfile=("http://[::3]", `sha256:{$sha256}`) )

            // Second degree refs and extended model
            ( _ext:model:form=invalid
                :client="tcp://[::1]"
                :server="tcp://[::2]"
                :url="http://[::3]"
                :ja3:sample=("tcp://[::1]", $md5_00)
                :ja3s:sample=("tcp://[::2]", $md5_00)
            )

            .seen = (2020, 2021)

            +#test.client.invalid
            +#test.server.invalid
            +#test.url.invalid
            +#test.tagprop:score = 0

            <(seen)+ {[ meta:source=(regression, 0.2.35) :type=synapse.regression ]}
        ]

        $node.data.set('addr', 'invalid')
        '''
        await core.callStorm(q, opts=infork00)

        # valid inet:client
        # valid inet:server
        # valid inet:url
        q = r'''[
            ( inet:client="tcp://::1" :_valid=(true) )
            ( inet:client="tcp://[::1]:80" :_valid=(true) )

            ( inet:server="tcp://::2" :_valid=(true) )
            ( inet:server="tcp://[::2]:80" :_valid=(true) )

            ( inet:url="http://::3" :_valid=(true) )
            ( inet:url="http://[::3]:80" :_valid=(true) )

            // linked props
            ( inet:flow=(regression 0.2.35, client00, valid) :src="tcp://::1" )
            ( inet:flow=(regression 0.2.35, client01, valid) :src="tcp://[::1]:80" )

            ( inet:flow=(regression 0.2.35, server00, valid) :dst="tcp://::2" )
            ( inet:flow=(regression 0.2.35, server01, valid) :dst="tcp://[::2]:80" )

            ( risk:vuln=(regression, 0.2.35, url00, valid) :cve:url="http://::3" )
            ( risk:vuln=(regression, 0.2.35, url01, valid) :cve:url="http://[::3]:80" )

            // linked comp types
            ( inet:tls:ja3:sample=("tcp://::1", $md5_00) )
            ( inet:tls:ja3:sample=("tcp://[::1]:80", $md5_00) )
            ( inet:tls:ja3s:sample=("tcp://::2", $md5_00) )
            ( inet:tls:ja3s:sample=("tcp://[::2]:80", $md5_00) )
            ( inet:urlfile=("http://::3", `sha256:{$sha256}`) )
            ( inet:urlfile=("http://[::3]:80", `sha256:{$sha256}`) )

            .seen = (2020, 2021)

            +#test.client.valid
            +#test.server.valid
            +#test.url.valid
            +#test.tagprop:score = 1

            <(seen)+ {[ meta:source=(regression, 0.2.35) :type=synapse.regression ]}
        ]

        $node.data.set('addr', 'valid')
        '''
        await core.callStorm(q, opts=infork00)

#        # props, ndefs, arrays
#        q = r'''
#            // valid inet:client
#            [( risk:vulnerable=(risk, client, valid)
#                :node=(inet:client, "tcp://::1")
#                +#test.risk.client.valid
#            )]
#
#            // 22valid, 23valid
#            [( it:prod:soft=(prod, 22v, 23v)
#                :name="22v-23v"
#                :cpe={ it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*" }
#                +#test.prod.22valid
#                +#test.prod.23valid
#            )]
#
#            // 22valid, 23invalid
#            [( it:prod:soft=(prod, 22v, 23i)
#                :name="22v-23i"
#                :cpe={ it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0" }
#                +#test.prod.22valid
#                +#test.prod.23invalid
#            )]
#
#            // 22invalid, 23valid
#            [( it:prod:soft=(prod, 22i, 23v)
#                :name="22i-23v"
#                :cpe={ it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*" }
#                +#test.prod.22invalid
#                +#test.prod.23valid
#            )]
#
#            // 22invalid, 23invalid
#            [( it:prod:soft=(prod, 22i, 23i)
#                :name="22i-23i"
#                :cpe={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*" }
#                +#test.prod.22invalid
#                +#test.prod.23invalid
#            )]
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        q = r'''
#            // 22valid, 23valid
#            [( inet:flow=(flow, 22v, 23v)
#                :dst:cpes+={ it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*" }
#                :dst:cpes+={ it:sec:cpe="cpe:2.3:a:abine:donottrackme_-_mobile_privacy:1.1.8:*:*:*:*:android:*:*" }
#                +#test.flow.22valid
#                +#test.flow.23valid
#            )]
#
#            // 22valid, 23invalid
#            [( inet:flow=(flow, 22v, 23i)
#                :dst:cpes+={ it:sec:cpe="cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~" }
#                :dst:cpes+={ it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0" }
#                +#test.flow.22valid
#                +#test.flow.23invalid
#            )]
#
#            // 22invalid, 23valid
#            [( inet:flow=(flow, 22i, 23v)
#                :src:cpes+={ it:sec:cpe="cpe:2.3:a:abinitio:control\\>center:-:*:*:*:*:*:*:*" }
#                :src:cpes+={ it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*" }
#                +#test.flow.22invalid
#                +#test.flow.23valid
#            )]
#
#            // 22invalid, 23invalid
#            [( inet:flow=(flow, 22i, 23i)
#                :src:cpes+={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:7.4\r\n:*:*:*:*:*:*:*" }
#                :src:cpes+={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*" }
#                :dst:cpes+={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*" }
#                +#test.flow.22invalid
#                +#test.flow.23invalid
#            )]
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        q = r'''
#            // 22valid, 23valid
#            [( _ext:model:form='22v-23v'
#                :cpe = "cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*"
#                +#test.ext.22valid
#                +#test.ext.23valid
#            )]
#
#            // 22valid, 23invalid
#            [( _ext:model:form='22v-23i'
#                :cpe = "cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~"
#                +#test.ext.22valid
#                +#test.ext.23invalid
#            )]
#
#            // 22invalid, 23valid
#            [( _ext:model:form='22i-23v'
#                :cpe = "cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*"
#                +#test.ext.22invalid
#                +#test.ext.23valid
#            )]
#
#            // 22invalid, 23invalid
#            [( _ext:model:form='22i-23i'
#                :cpe = "cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*"
#                +#test.ext.22invalid
#                +#test.ext.23invalid
#            )]
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        q = r'''
#            it:sec:cpe#test.cpe.22invalid
#            [ <(seen)+ {[ meta:source=(cpe, 22, invalid) :name="cpe.22.invalid" ]} ]
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        q = r'''
#            it:sec:cpe#test.cpe.23invalid
#            [ <(seen)+ {[ meta:source=(cpe, 23, invalid) :name="cpe.23.invalid" ]} ]
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        q = r'''
#            it:sec:cpe#test.cpe.22invalid
#
#            $cpe = $node
#            $source = { meta:source:name="cpe.22.invalid" }
#
#            [ meta:seen=($source, $cpe.ndef()) ]
#
#            // Add another degree of references that we have to deal with in the migration
#            { +meta:seen
#                $seen = $node
#                [( it:sec:vuln:scan:result=(meta:seen, $seen.iden()) :asset=$seen.ndef() )]
#            }
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        q = r'''
#            it:sec:cpe#test.cpe.23invalid
#
#            $cpe = $node
#            $source = { meta:source:name="cpe.23.invalid" }
#
#            [ meta:seen=($source, $cpe.ndef()) ]
#
#            // Add another degree of references that we have to deal with in the migration
#            { +meta:seen
#                $seen = $node
#                [( it:sec:vuln:scan:result=(meta:seen, $seen.iden()) :asset=$seen.ndef() )]
#            }
#        '''
#        await core.callStorm(q, opts=infork01)
#
#        # Primary and v2_2 valid in lower layer, v2_2 invalid in fork
#        q = r'''
#            it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*"
#            [ :v2_2 = "cpe:/a:01generator:pireospay\r\n:-::~~~prestashop~~" ]
#        '''
#        await core.callStorm(q, opts=infork02)
#
#        # Primary and v2_2 invalid in lower layer, v2_2 valid in fork
#        q = r'''
#            it:sec:cpe="cpe:2.3:a:openbsd:openssh:7.4\r\n:*:*:*:*:*:*:*"
#            [ :v2_2 = "cpe:/a:openbsd:openssh_server:7.4" ]
#        '''
#        await core.callStorm(q, opts=infork02)
#
#        q = '''
#            it:sec:cpe#test.cpe.23valid +#test.cpe.22invalid
#            [
#                :_cpe22valid = (true)
#                :_cpe23valid = (true)
#
#                .seen = 2023
#
#                <(seen)+ {[ meta:source=(cpe, 22, wasinvalid) :name="cpe.22.wasinvalid" ]}
#                <(seen)+ {[ meta:source=(cpe, 23, valid) :name="cpe.23.valid" ]}
#
#                +(refs)> {[ meta:source=(cpe, 22, wasinvalid) :name="cpe.22.wasinvalid" ]}
#                +(refs)> {[ meta:source=(cpe, 23, valid) :name="cpe.23.valid" ]}
#
#                -#test.cpe.22invalid
#                +#test.cpe.22valid
#                +#test.tagprop:score = 11
#            ]
#
#            $node.data.set('cpe22', 'wasinvalid')
#            $node.data.set('cpe23', 'valid')
#        '''
#        await core.callStorm(q, opts=infork02)
#
#        q = '''
#            it:sec:cpe#test.cpe.22valid +#test.cpe.23invalid
#            [
#                :_cpe22valid = (true)
#                :_cpe23valid = (true)
#
#                .seen = 2024
#
#                <(seen)+ {[ meta:source=(cpe, 22, valid) :name="cpe.22.valid" ]}
#                <(seen)+ {[ meta:source=(cpe, 23, wasinvalid) :name="cpe.23.wasinvalid" ]}
#
#                +(refs)> {[ meta:source=(cpe, 22, valid) :name="cpe.22.valid" ]}
#                +(refs)> {[ meta:source=(cpe, 23, wasinvalid) :name="cpe.23.wasinvalid" ]}
#
#                -#test.cpe.23invalid
#                +#test.cpe.23valid
#                +#test.tagprop:score = 11
#            ]
#
#            $node.data.set('cpe22', 'valid')
#            $node.data.set('cpe23', 'wasinvalid')
#        '''
#        await core.callStorm(q, opts=infork02)
#
#        q = r'''[
#            ( it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*"
#                :v2_2="cpe:/a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2"
#            )
#
#            ( it:sec:cpe="cpe:2.3:a:%40ianwalter:merge:*:*:*:*:*:*:*:*"
#                :v2_2="cpe:/a:%40ianwalter:merge"
#            )
#        ]
#        '''
#        await core.callStorm(q, opts=infork03)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
