# generate the model version 0.1.0 regression cortex
# ( must use synapse code prior to source -> meta:source )
import os
import shutil
import asyncio

import synapse.common as s_common
import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

destpath = 'cortexes/pre-010'

async def main():

    with s_common.getTempDir() as dirn:

        path = os.path.join(dirn, 'cortex')

        #sorc = s_common.guid()
        #plac = s_common.guid()
        #pers = s_common.guid()
        #evnt = s_common.guid()
        #clus = s_common.guid()
    
        sorc = 'a6246e97d7b02e2dcc90dd117611a981'
        plac = '36c0959d703b9d16e7566a858234bece'
        pers = '83fc390015c0c0ed054d09e87aa31853'
        evnt = '7156b48f84de79d3a375baa3c7904387'
        clus = 'fae28e60d8af681f12109d6da0c48555'

        #53c5777bcd9803c8d1d8260b1e93178f
        #7dd37c4db8b49ad9847610f5de906f9b
        #b49d62012d968c31abf3393a207bdd0c
        #f31b02decb765da091eeef678e544531
        #fcbb8a27fb19671297ea12bf69def52e

        async with await s_cortex.Cortex.anit(path) as core:

            [ n async for n in core.eval(f'[ source={sorc} +#hehe .seen=2019 ]') ]

            # besides checking seen conversion, this also checks comp prop conversion via source
            [ n async for n in core.eval(f'[ inet:dns:a=(vertex.link, 1.2.3.4) seen=({sorc}, $node) +#hehe .seen=2019 ]') ]

            [ n async for n in core.eval(f'[ has=((ps:person, {pers}), (geo:place, {plac})) +#hehe .seen=2019 ]') ]
            [ n async for n in core.eval(f'[ refs=((ps:person, {pers}), (geo:place, {plac})) +#hehe .seen=2019 ]') ]
            [ n async for n in core.eval(f'[ wentto=((ps:person, {pers}), (geo:place, {plac}), 2019) +#hehe .seen=2019 ]') ]

            # use the cluster -> refs -> node relationship to test ndef rewrites
            [ n async for n in core.eval(f'[ cluster={clus} refs=($node, (inet:fqdn, vertex.link)) +#hehe .seen=2019 ]') ]

            [ n async for n in core.eval(f'[ event={evnt} +#hehe .seen=2019 ]') ]
            [ n async for n in core.eval(f'[ graph:link=((ps:person, {pers}), (geo:place, {plac})) +#hehe .seen=2019 ]') ]
            [ n async for n in core.eval(f'[ graph:timelink=((ps:person, {pers}), (geo:place, {plac}), 2019) +#hehe .seen=2019 ]') ]

            async with core.getLocalProxy() as prox:
                await prox.addCronJob('inet:ipv4', {'dayofweek': 3})
                await prox.addTrigger('tag:add', '[ +#yerp ]', info={'tag': 'newp'})

        # only run this from the checkout dir... :)
        shutil.rmtree(destpath, ignore_errors=True)

        s_backup.backup(path, destpath)

if __name__ == '__main__':
    asyncio.run(main())
