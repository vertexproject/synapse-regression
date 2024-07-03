import shutil

import synapse.lib.msgpack as s_msgpack
import synapse.tools.backup as s_backup
import synapse.tests.utils as s_t_utils

class GenCore(s_t_utils.SynTest):

    async def test_gen_layer_v11(self):

        dst_dirn = 'cortexes/layer-v11'

        with self.getTestDir() as src_dirn:

            async with self.getTestCore(dirn=src_dirn) as core:

                await core.nodes('$lib.model.ext.addTagProp(score, (int, ({})), ({}))')

                view_prop = await core.callStorm('return($lib.view.get().fork(name=prop).iden)')
                view_tags = await core.callStorm('return($lib.view.get().fork(name=tags).iden)')
                view_tagp = await core.callStorm('return($lib.view.get().fork(name=tagp).iden)')
                view_n1eg = await core.callStorm('return($lib.view.get().fork(name=n1eg).iden)')
                view_n2eg = await core.callStorm('return($lib.view.get().fork(name=n2eg).iden)')
                view_data = await core.callStorm('return($lib.view.get().fork(name=data).iden)')
                view_noop = await core.callStorm('return($lib.view.get().fork(name=noop).iden)')

                self.len(2, await core.nodes('[ test:str=foo test:str=bar +#base ]'))
                self.len(1, await core.nodes('test:str=foo [ :hehe=haha ]', opts={'view': view_prop}))
                self.len(1, await core.nodes('test:str=foo [ +#bar ]', opts={'view': view_tags}))
                self.len(1, await core.nodes('test:str=foo [ +#base:score=10 ]', opts={'view': view_tagp}))
                self.len(1, await core.nodes('test:str=foo [ +(bam)> {[ test:int=2 ]} ]', opts={'view': view_n1eg}))
                self.len(1, await core.nodes('test:str=foo [ <(bam)+ {[ test:int=1 ]} ]', opts={'view': view_n2eg}))
                self.len(1, await core.nodes('test:str=foo $node.data.set(hehe, haha)', opts={'view': view_data}))

                # put a bad sode in the default layer for coverage
                layr = core.getLayer()
                layr.layrslab.put(b'\x00' * 32, s_msgpack.en({}), db=layr.bybuidv3)

            shutil.rmtree(dst_dirn, ignore_errors=True)

            s_backup.backup(src_dirn, dst_dirn)
