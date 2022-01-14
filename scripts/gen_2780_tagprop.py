import asyncio

import synapse.tests.utils as s_t_utils

'''
Generate the 2.78.0-tagprop-missing-indx cortex. It breaks a sode so we have a
situation that will require migration.

This should be run on v2.77.0.
'''


class GenCore(s_t_utils.SynTest):

    async def test_genv7_regr(self):
        async with self.getTestCore(dirn='./testv7migr') as core:
            await core.nodes('$lib.model.ext.addTagProp(comment, (str, $lib.dict()), $lib.dict())')
            nodes = await core.nodes('[ inet:ipv4=1.2.3.1 :asn=10 +#bar ]')
            nodes = await core.nodes('[ inet:ipv4=1.2.3.2 :asn=10 +#foo:comment=foo ]')
            nodes = await core.nodes('[ inet:ipv4=1.2.3.4 :asn=20 +#foo:comment=words ]')
            buid = nodes[0].buid

            layr = core.getLayer()
            sode = await layr.getStorNode(buid)
            tagprops = {('foo', 'comment'): ('words', 1)}
            sode['tagprops'] = tagprops
            layr.setSodeDirty(buid, sode, sode.get('form'))
            await asyncio.sleep(5)
