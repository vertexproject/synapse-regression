import asyncio

import synapse.lib.version as s_version

import synapse.tests.utils as s_t_utils

'''
Generate the 2.86.0-crypto-geo cortex.

This should be run on v2.86.0.
'''


class GenCore(s_t_utils.SynTest):

    async def test_gen2870_migr(self):
        self.eq(s_version.verstring, '2.86.0')
        async with self.getTestCore(dirn='./test2870migr') as core:

            nodes = await core.nodes('[(geo:place=(t0,)) (geo:place=(t1,) :name=" Big Hollywood  sign ")]')
            nodes = await core.nodes('[(crypto:currency:block=(vcoin, 1234) :hash=0x73f82fa9fd7f65fc30c3d4d24b5942c4 )]')
            nodes = await core.nodes('[(crypto:currency:transaction=(t1,) :hash=0x0c3d4d24b5942c473f82fa9fd7f65fc3 )]')
            nodes = await core.nodes('[(crypto:currency:transaction=(t2,) :inputs=((i1,), (i2,),) :outputs=((o1,), (o2,),) )]')
            nodes = await core.nodes('[(crypto:currency:transaction=(t3,) :inputs=((i3,), (i2,),) :outputs=((o3,), (o2,),) )]')
            nodes = await core.nodes('[(crypto:payment:input=(i4,) )]')
            nodes = await core.nodes('[(crypto:payment:output=(o4,) )]')

            await asyncio.sleep(2)
