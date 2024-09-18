import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    maxver = (2, 169, 0)
    if s_version.version > (2, 169, 0):
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = 'model-0.2.28'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # Add extended model forms that have secondary props of
        await core.addForm('_ext:model:form', 'str', {}, {})
        await core.addFormProp('_ext:model:form', 'cpe', ('it:sec:cpe', {}), {})
        await core.addFormProp('it:sec:cpe', '_cpe22valid', ('bool', {}), {})
        await core.addFormProp('it:sec:cpe', '_cpe23valid', ('bool', {}), {})

        fork00 = await core.callStorm('return($lib.view.get().fork().iden)')
        infork00 = {'view': fork00}
        print(f'{fork00=}')

        fork01 = await core.callStorm('return($lib.view.get().fork().iden)', opts=infork00)
        infork01 = {'view': fork01}
        print(f'{fork01=}')

        fork02 = await core.callStorm('return($lib.view.get().fork().iden)', opts=infork01)
        infork02 = {'view': fork02}
        print(f'{fork02=}')

        # CPE2.3 valid, CPE2.2 valid
        q = r'''[
            ( it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*"
                :v2_2="cpe:/a:01generator:pireospay:-::~~~prestashop~~"
            )

            ( it:sec:cpe="cpe:2.3:a:abine:donottrackme_-_mobile_privacy:1.1.8:*:*:*:*:android:*:*"
                :v2_2="cpe:/a:abine:donottrackme_-_mobile_privacy:1.1.8::~~~android~~"
            )

            :_cpe22valid = (true)
            :_cpe23valid = (true)

            .seen = (2020, 2021)

            +#test.cpe.23valid
            +#test.cpe.22valid

            +(refs)> {[ risk:vuln=(risk, vuln) ]}
        ]

        $node.data.set('cpe22', 'valid')
        $node.data.set('cpe23', 'valid')

        { +it:sec:cpe
            $ndef = $node.ndef()
            [( risk:vulnerable=(22valid, 23valid, $ndef) :node=$ndef )]
        }
        '''
        await core.callStorm(q, opts=infork00)

        # CPE2.3 invalid, CPE2.2 invalid
        q = r'''[
            ( it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*"
                :v2_2="cpe:/a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2"
            )

            ( it:sec:cpe="cpe:2.3:a:openbsd:openssh:7.4\r\n:*:*:*:*:*:*:*"
                :v2_2="cpe:/a:openbsd:openssh:7.4\r\n"
            )

            :_cpe22valid = (false)
            :_cpe23valid = (false)

            .seen = (2020, 2021)

            +#test.cpe.23invalid
            +#test.cpe.22invalid

            +(refs)> {[ risk:vuln=(risk, vuln) ]}
        ]

        $node.data.set('cpe22', 'invalid')
        $node.data.set('cpe23', 'invalid')

        { +it:sec:cpe
            $ndef = $node.ndef()
            [( risk:vulnerable=(22invalid, 23invalid, $ndef) :node=$ndef )]
        }
        '''
        await core.callStorm(q, opts=infork00)

        # CPE2.3 valid, CPE2.2 invalid
        q = r'''[
            it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*"
            it:sec:cpe="cpe:2.3:a:abinitio:control\\>center:-:*:*:*:*:*:*:*"
            it:sec:cpe="cpe:/o:zyxel:nas542_firmware:5.21\%28aazf.15\%29co"

            :_cpe22valid = (false)
            :_cpe23valid = (true)

            .seen = (2020, 2021)

            +#test.cpe.23valid
            +#test.cpe.22invalid

            +(refs)> {[ risk:vuln=(risk, vuln) ]}
        ]

        $node.data.set('cpe22', 'invalid')
        $node.data.set('cpe23', 'valid')

        { +it:sec:cpe
            $ndef = $node.ndef()
            [( risk:vulnerable=(22invalid, 23valid, $ndef) :node=$ndef )]
        }
        '''
        await core.callStorm(q, opts=infork00)

        # CPE2.3 invalid, CPE2.2 valid
        q = r'''[
            it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0"
            it:sec:cpe="cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~"
            it:sec:cpe="cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~"
            ( it:sec:cpe="cpe:2.3:h:d\\-link:dir\\-850l:*:*:*:*:*:*:*:*"
                :v2_2="cpe:/h:d-link:dir-850l"
            )

            :_cpe22valid = (true)
            :_cpe23valid = (false)

            .seen = (2020, 2021)

            +#test.cpe.23invalid
            +#test.cpe.22valid

            +(refs)> {[ risk:vuln=(risk, vuln) ]}
        ]

        $node.data.set('cpe22', 'valid')
        $node.data.set('cpe23', 'invalid')

        { +it:sec:cpe
            $ndef = $node.ndef()
            [( risk:vulnerable=(22valid, 23invalid, $ndef) :node=$ndef )]
        }
        '''
        await core.callStorm(q, opts=infork00)

        # Creating the risk:vulnerable node causes a re-norm of this node and
        # overwrites the valid v2_2 prop. Fix it here.
        await core.callStorm('it:sec:cpe="cpe:2.3:h:d\\-link:dir\\-850l:*:*:*:*:*:*:*:*" [ :v2_2="cpe:/h:d-link:dir-850l" ]', opts=infork00)

        q = r'''
            // 22valid, 23valid
            [( it:prod:soft=(prod, 22v, 23v)
                :name="22v-23v"
                :cpe={ it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*" }
                +#test.prod.22valid
                +#test.prod.23valid
            )]

            // 22valid, 23invalid
            [( it:prod:soft=(prod, 22v, 23i)
                :name="22v-23i"
                :cpe={ it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0" }
                +#test.prod.22valid
                +#test.prod.23invalid
            )]

            // 22invalid, 23valid
            [( it:prod:soft=(prod, 22i, 23v)
                :name="22i-23v"
                :cpe={ it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*" }
                +#test.prod.22invalid
                +#test.prod.23valid
            )]

            // 22invalid, 23invalid
            [( it:prod:soft=(prod, 22i, 23i)
                :name="22i-23i"
                :cpe={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*" }
                +#test.prod.22invalid
                +#test.prod.23invalid
            )]
        '''
        await core.callStorm(q, opts=infork01)

        q = r'''
            // 22valid, 23valid
            [( inet:flow=(flow, 22v, 23v)
                :dst:cpes+={ it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*" }
                :dst:cpes+={ it:sec:cpe="cpe:2.3:a:abine:donottrackme_-_mobile_privacy:1.1.8:*:*:*:*:android:*:*" }
                +#test.flow.22valid
                +#test.flow.23valid
            )]

            // 22valid, 23invalid
            [( inet:flow=(flow, 22v, 23i)
                :dst:cpes+={ it:sec:cpe="cpe:/a:10web:social_feed_for_instagram:1.0.0::~~premium~wordpress~~" }
                :dst:cpes+={ it:sec:cpe="cpe:/o:zyxel:nas326_firmware:5.21%28AAZF.14%29C0" }
                +#test.flow.22valid
                +#test.flow.23invalid
            )]

            // 22invalid, 23valid
            [( inet:flow=(flow, 22i, 23v)
                :src:cpes+={ it:sec:cpe="cpe:2.3:a:abinitio:control\\>center:-:*:*:*:*:*:*:*" }
                :src:cpes+={ it:sec:cpe="cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*" }
                +#test.flow.22invalid
                +#test.flow.23valid
            )]

            // 22invalid, 23invalid
            [( inet:flow=(flow, 22i, 23i)
                :src:cpes+={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:7.4\r\n:*:*:*:*:*:*:*" }
                :src:cpes+={ it:sec:cpe="cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*" }
                +#test.flow.22invalid
                +#test.flow.23invalid
            )]
        '''
        await core.callStorm(q, opts=infork01)

        q = r'''
            // 22valid, 23valid
            [( _ext:model:form='22v-23v'
                :cpe = "cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*"
                +#test.ext.22valid
                +#test.ext.23valid
            )]

            // 22valid, 23invalid
            [( _ext:model:form='22v-23i'
                :cpe = "cpe:/a:acurax:under_construction_%2f_maintenance_mode:-::~~~wordpress~~"
                +#test.ext.22valid
                +#test.ext.23invalid
            )]

            // 22invalid, 23valid
            [( _ext:model:form='22i-23v'
                :cpe = "cpe:2.3:a:1c:1c\\:enterprise:-:*:*:*:*:*:*:*"
                +#test.ext.22invalid
                +#test.ext.23valid
            )]

            // 22invalid, 23invalid
            [( _ext:model:form='22i-23i'
                :cpe = "cpe:2.3:a:openbsd:openssh:8.2p1 ubuntu-4ubuntu0.2:*:*:*:*:*:*:*"
                +#test.ext.22invalid
                +#test.ext.23invalid
            )]
        '''
        await core.callStorm(q, opts=infork01)

        q = r'''
            it:sec:cpe#test.cpe.22invalid
            [ <(seen)+ {[ meta:source=(cpe, 22, invalid) :name="cpe.22.invalid" ]} ]
        '''
        await core.callStorm(q, opts=infork01)

        q = r'''
            it:sec:cpe#test.cpe.23invalid
            [ <(seen)+ {[ meta:source=(cpe, 23, invalid) :name="cpe.23.invalid" ]} ]
        '''
        await core.callStorm(q, opts=infork01)

        q = r'''
            it:sec:cpe#test.cpe.22invalid

            $cpe = $node
            $source = { meta:source:name="cpe.22.invalid" }

            [ meta:seen=($source, $cpe.ndef()) ]

            // Add another degree of references that we have to deal with in the migration
            { +meta:seen
                $seen = $node
                [( it:sec:vuln:scan:result=(meta:seen, $seen.iden()) :asset=$seen.ndef() )]
            }
        '''
        await core.callStorm(q, opts=infork01)

        q = r'''
            it:sec:cpe#test.cpe.23invalid

            $cpe = $node
            $source = { meta:source:name="cpe.23.invalid" }

            [ meta:seen=($source, $cpe.ndef()) ]

            // Add another degree of references that we have to deal with in the migration
            { +meta:seen
                $seen = $node
                [( it:sec:vuln:scan:result=(meta:seen, $seen.iden()) :asset=$seen.ndef() )]
            }
        '''
        await core.callStorm(q, opts=infork01)

        # Primary and v2_2 valid in lower layer, v2_2 invalid in fork
        q = r'''
            it:sec:cpe="cpe:2.3:a:01generator:pireospay:-:*:*:*:*:prestashop:*:*"
            [ :v2_2 = "cpe:/a:01generator:pireospay\r\n:-::~~~prestashop~~" ]
        '''
        await core.callStorm(q, opts=infork02)

        # Primary and v2_2 invalid in lower layer, v2_2 valid in fork
        q = r'''
            it:sec:cpe="cpe:2.3:a:openbsd:openssh:7.4\r\n:*:*:*:*:*:*:*"
            [ :v2_2 = "cpe:/a:openbsd:openssh:7.4" ]
        '''
        await core.callStorm(q, opts=infork02)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
