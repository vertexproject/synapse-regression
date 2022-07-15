import os
import asyncio
import synapse.common as s_common
import synapse.lib.hive as s_hive
import synapse.lib.lmdbslab as s_lmdbslab

oldvers = (0, 2, 8)
newvers = (0, 2, 9)

async def main():
    s_common.gendir('slabs')

    path = os.path.join('layers', 'ab3639bbb5d87ce6fb778412570bb58f', 'layer_v2.lmdb')
    if not os.path.exists(path):
        print('No db found!')
        return

    slab = await s_lmdbslab.Slab.anit(path)
    db = slab.initdb('layer:meta')
    hive = s_lmdbslab.SlabDict(slab, db=db)
    print(hive.get('version'))
    hive.set('version', 9223372036854775807)
    await slab.fini()
    return

    for name, info in node:
        layrinfo = await info.dict()
        layrvers = layrinfo.get('model:version')
        print(f'Layer {name} version {layrvers}')
        if layrvers == oldvers:
            print(f'Updating layer {name} to {newvers}')
            await layrinfo.set('model:version', newvers)

    await slab.fini()

asyncio.run(main())
