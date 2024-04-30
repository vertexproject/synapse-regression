import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    tmpdir = '/tmp/v/hive-migration'
    modldir = 'cortexes/hive-migration'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        visi = await core.auth.addUser('visi')
        await visi.addRule((True, ('cron' ,'add')))
        await visi.addRule((True, ('dmon' ,'add')))
        await visi.addRule((True, ('trigger' ,'add')))

        asvisi = {'user': visi.iden}

        await core.nodes('cron.add --hour +1 {[tel:mob:telem=*]} --name myname --doc mydoc', opts=asvisi)
        await core.nodes('trigger.add tag:add --form test:str --tag footag.* --query {[ +#count test:str=$tag ]}', opts=asvisi)

        await core.nodes('$lib.dmon.add(${ $lib.print(foobar) $lib.time.sleep(10) }, name=foodmon)', opts=asvisi)

        await core.nodes('$lib.user.vars.set(foovar, barvalu)', opts=asvisi)
        await core.nodes('$lib.user.profile.set(fooprof, barprof)', opts=asvisi)

        await core.callStorm('''
            $typeinfo = ({})
            $forminfo = ({"doc": "A test form doc."})
            $lib.model.ext.addForm(_visi:int, int, $typeinfo, $forminfo)

            $propinfo = ({"doc": "A test prop doc."})
            $lib.model.ext.addFormProp(_visi:int, tick, (time, ({})), $propinfo)

            $univinfo = ({"doc": "A test univ doc."})
            $lib.model.ext.addUnivProp(_woot, (int, ({})), $univinfo)

            $tagpropinfo = ({"doc": "A test tagprop doc."})
            $lib.model.ext.addTagProp(score, (int, ({})), $tagpropinfo)
        ''')
        await core.nodes('[ _visi:int=10 :tick=2020 ._woot=5 +#test:score=6]')
        await core.setTagModel('test', 'regex', (None, '[0-9]{4}'))

        await core.nodes('model.deprecated.lock ou:hasalias')

        cdef = {
            'name': 'testcmd0',
            'cmdargs': (
                ('foo', {}),
            ),
            'cmdconf': {
                'hehe': 'haha',
            },
            'storm': '$lib.print(`{$cmdopts.foo} {$cmdconf.hehe}`)',
        }
        await core.setStormCmd(cdef)

        await core.nodes('''$lib.pkg.add(({
          "name": "testpkg", 
          "version": "1.0.0", 
          "commands": [{
             "name": "testcmd1",
             "storm": "$lib.print(hello)",
          }],
         }))''')

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
