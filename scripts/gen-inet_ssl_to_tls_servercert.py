
import shutil
import asyncio

import synapse.cortex as s_cortex

import synapse.tools.backup as s_backup

async def main():

    name = 'inet_ssl_to_tls_servercert'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        await core.callStorm('[ meta:source=* :name=ssl_migration ]')

        # inet:ssl:cert where the inet:ssl:cert and the crypto:x509:cert are
        # both linked the the same file
        q = '''
            $file = {
                [ file:bytes=*
                    :sha256 = 79be0eb36e6687b7e5e8dfb2c12db8d70f7d0e04da908b3b70820f2accd8d92e
                ]

            }

            $server = { [ inet:server=tcp://1.2.3.4:443 ] }

            [
                ( inet:ssl:cert=($server, $file) .seen = 20230710
                    +#ssl.migration.one
                    <(seen)+ { meta:source:name=ssl_migration }
                )

                ( crypto:x509:cert=(cert1,) :file=$file )
            ]
        '''
        await core.callStorm(q)

        # inet:ssl:cert where the inet:ssl:cert is linked to a file and the
        # crypto:x509:cert has the same sha256 as the file
        q = '''
            $sha256 = 4712a2ab85f6fb3f1d9e8e6adbc42fdec4f8aca4167b6dbe6627a59f2ca03da8
            $file = { [ file:bytes = $sha256 ] }


            $server = { [ inet:server="tcp://[fe80::1]:8080" ] }

            [
                ( inet:ssl:cert=($server, $file) 
                    +#ssl.migration.two
                    <(seen)+ { meta:source:name=ssl_migration }
                )

                ( crypto:x509:cert=(cert2,) :sha256=$sha256 )
            ]
        '''
        await core.callStorm(q)

        # inet:ssl:cert where the file doesn't have a linked crypto:x509:cert
        q = '''
        [ inet:ssl:cert=(tcp://8.8.8.8:53, aa0366ffb013ba2053e45cd7e4bcc8acd6a6c1bafc82eddb4e155876734c5e25)
            +#ssl.migration.three
            <(seen)+ { meta:source:name=ssl_migration }
        ]
        $node.data.set(foo, bar)
        '''
        await core.callStorm(q)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
