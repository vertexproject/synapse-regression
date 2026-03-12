import shutil
import asyncio

import synapse.common as s_common
import synapse.cortex as s_cortex

import synapse.lib.layer as s_layer
import synapse.lib.modelrev as s_modelrev

import synapse.tools.backup as s_backup

async def main():

    name = 'model-0.2.35'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # Create an IPv4 control node (should not be affected by migration)
        await core.nodes('[inet:server="tcp://127.0.0.1:80"]')

        # Get the default layer for raw edits
        layr = core.getLayer()
        meta = {'time': s_common.now(), 'user': core.auth.rootuser.iden}

        # Helper to inject a raw node with bare IPv6 value
        async def addBareNode(formname, formvalu, props=None, tags=None):
            form = core.model.form(formname)
            stortype = form.type.stortype
            buid = s_common.buid((formname, formvalu))

            edits = [
                (s_layer.EDIT_NODE_ADD, (formvalu, stortype), ()),
            ]

            # Add .created
            edits.append(
                (s_layer.EDIT_PROP_SET, ('.created', s_common.now(), None, s_layer.STOR_TYPE_MINTIME), ())
            )

            if props:
                for propname, propvalu, propstortype in props:
                    edits.append(
                        (s_layer.EDIT_PROP_SET, (propname, propvalu, None, propstortype), ())
                    )

            if tags:
                for tagname, tagvalu in tags:
                    edits.append(
                        (s_layer.EDIT_TAG_SET, (tagname, tagvalu, None), ())
                    )

            nodeedits = [(buid, formname, edits)]
            await layr.storNodeEditsNoLift(nodeedits, meta)
            return buid

        # Inject inet:server with bare IPv6 (old format: tcp://::1)
        await addBareNode('inet:server', 'tcp://::1', props=[
            ('proto', 'tcp', s_layer.STOR_TYPE_UTF8),
            ('ipv6', '::1', s_layer.STOR_TYPE_UTF8),
        ], tags=[
            ('test.server', (None, None)),
        ])

        # Inject inet:client with bare IPv6 (no port)
        await addBareNode('inet:client', 'tcp://::1', props=[
            ('proto', 'tcp', s_layer.STOR_TYPE_UTF8),
            ('ipv6', '::1', s_layer.STOR_TYPE_UTF8),
        ], tags=[
            ('test.client', (None, None)),
        ])

        # Inject inet:url with bare IPv6
        await addBareNode('inet:url', 'http://::1/index.html', props=[
            ('proto', 'http', s_layer.STOR_TYPE_UTF8),
            ('ipv6', '::1', s_layer.STOR_TYPE_UTF8),
            ('path', '/index.html', s_layer.STOR_TYPE_UTF8),
            ('params', '', s_layer.STOR_TYPE_UTF8),
            ('base', 'http://::1/index.html', s_layer.STOR_TYPE_UTF8),
            ('port', 80, s_layer.STOR_TYPE_U16),
        ])

        # Inject inet:banner comp form referencing the bare IPv6 server
        # inet:banner = (server, text) where server is inet:server type
        bannervalu = ('tcp://::1', 'hello')
        await addBareNode('inet:banner', bannervalu, props=[
            ('server', 'tcp://::1', s_layer.STOR_TYPE_UTF8),
            ('server:proto', 'tcp', s_layer.STOR_TYPE_UTF8),
            ('server:ipv6', '::1', s_layer.STOR_TYPE_UTF8),
            ('text', 'hello', s_layer.STOR_TYPE_UTF8),
        ])

        # Set model version back to (0, 2, 34) so migration will run
        await layr._setModelVers((0, 2, 34))

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
