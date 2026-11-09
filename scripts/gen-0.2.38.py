import sys
import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.modelrev as s_modelrev

import synapse.tools.backup as s_backup

# inet:url values the migration repairs or quarantines. Each is stored by the
# pre-fix normalizer running under python -O (asserts stripped), which is how the
# Synapse docker images run. The comment on each value gives its stored form.
COLLAPSE = (
    'http:////foo.com/x',               # A: known scheme, collapses to http://foo.com/x
    'https://///1.2.3.4:81/x',          # A: stored https:////1.2.3.4:81/x
    'smb:////s',                        # A: stored smb:////s, collapses to smb://s
    'http:////@foo.com',                # A: empty auth, stored http:////foo.com
)

UNKNOWN_SCHEME = (
    'c:////spam////eggs',               # A: c is a drive letter, not a known scheme
    'dvdnav:////dev/sr1',               # A: not a registered scheme
    'a:b:////foo.com/x',                # A: scheme contains a colon
    'x?y:////h/s',                      # A: scheme contains a question mark
)

FIXPROPS = (
    # B: the value is valid, but :proto and the host came from the embedded URL.
    'http://foo.com/r?u=https:////evil.com/x',
    # B: as above, and the embedded auth part also set :user.
    'http://foo.com/r?u=https:////u@evil.com/x',
)

BROKEN = (
    # B: :proto came from the embedded URL and the stored value no longer normalizes.
    'smb:///.//c:////spam////eggs',
)

NOSCHEME = (
    # D: no valid scheme before the first :// (accepted with or without -O).
    '//www.example.com/submit?url=https://example.org/x',
    '/share?u=http://example.net/a',
    'www.example.com/submit?url=https://example.org/x',
    'mailto:visi@vertex.link?x=http://example.net',
    '1http://example.com',
    # D: normalizes to file:///foo?x=http://a once scheme validation is in place.
    'file:/foo?x=http://a',
)

AUTHORITY = (
    'file://user@/x',                   # userinfo and no host
    'http://u:pa#ss@b.example/x',       # the # ends the host, leaving no valid port
    'file://@/x',                       # stored file:///x with an empty :user
    # a # in the userinfo, so :fqdn and :user came from the fragment
    'https://login.example.net#first.last@example.com',
    'https://a.example#u:p@b.example',
    # Windows WebDAV hosts, whose port was stored as an IPv4 host @0.0.x.y
    'file://1.2.3.4@80/t.htm',
    'file://host@SSL@443/x',
    'file://u@host@80/x',
    'file://host@ssl/x',                # no port, the SSL marker is normalized
)

UNTOUCHED = (
    'file://user@host.vertex.link/share/x',  # userinfo and a host, which is valid
    'http:////u:p@foo.com/x',           # C: stored http://u:p@foo.com/x, which is valid
    'file:////host/share/x',            # valid UNC file URL
    'FILE://///host2/share/x',          # valid UNC file URL, stored file:////host2/share/x
    'https://good.com/x',
    'git+ssh://vertex.link/x',
    'chrome-extension://vertex.link/x',
)

async def main():

    # The bad values only exist in cortexes which ran the pre-fix inet:url
    # normalizer with asserts stripped, so refuse to run unless that is the case.
    if not sys.flags.optimize:
        mesg = 'This regression cortex MUST be generated with python -O.'
        raise s_exc.BadVersion(mesg=mesg)

    if s_modelrev.maxvers >= (0, 2, 38):
        mesg = f'This regression cortex MUST be generated before model revision 0.2.38, not {s_modelrev.maxvers}.'
        raise s_exc.BadVersion(mesg=mesg, curv=str(s_modelrev.maxvers))

    name = 'model-0.2.38'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        # The version check alone does not catch a checkout which already carries
        # the SYN-12067 fix, so check the normalizer directly.
        try:
            valu, _ = core.model.type('inet:url').norm('http:////foo.com/x')
        except s_exc.BadTypeValu:
            valu = None

        if valu != 'http:////foo.com/x':
            mesg = 'This regression cortex MUST be generated with the pre-SYN-12067 inet:url normalizer.'
            raise s_exc.BadVersion(mesg=mesg)

        await core.addTagProp('score', ('int', {}), {})

        for valu in COLLAPSE + UNKNOWN_SCHEME + FIXPROPS + BROKEN + NOSCHEME + AUTHORITY + UNTOUCHED:
            await core.nodes('[ inet:url=$valu ]', opts={'vars': {'valu': valu}})

        # A fully populated bad node, so the moved node can be checked for tags,
        # tag properties, nodedata, edges in both directions and references.
        await core.nodes('''
            inet:url="http:////foo.com/x"
            [ +#rep.test=(2020, 2021) +#rep.test:score=10 ]
            $node.data.set(woot, hehe)
            [ <(refs)+ { [ meta:source=9e9a0e4d3e2b4b1e8f0a1c2d3e4f5a6b :name="migration test source" ] } ]
            [ +(refs)> { [ inet:fqdn=vertex.link ] } ]
        ''')

        # Scalar, array and read-only comp references to the collapsing node.
        await core.nodes('[ media:news=* :title="scalar ref" :url="http:////foo.com/x" ]')
        await core.nodes('[ it:sec:cve=CVE-2026-12067 :references=("http:////foo.com/x", https://good.com/x) ]')
        await core.nodes('[ inet:urlredir=("http:////foo.com/x", https://good.com/x) +#redir.one ]')

        # A comp which also embeds a field of another type.
        await core.nodes('[ inet:urlfile=("http:////foo.com/x", "*") ]')

        # A redirect which embeds the same bad URL twice, and one which embeds two
        # different bad URLs, so one comp node is reached through two references.
        await core.nodes('[ inet:urlredir=("http:////foo.com/x", "http:////foo.com/x") ]')
        await core.nodes('[ inet:urlredir=("http:////foo.com/x", "smb:////s") ]')

        # A bad node whose collapsed value already exists, with conflicting tag
        # properties and nodedata, so the move has to merge.
        await core.nodes('''
            [ inet:url="http:////exists.com/y" +#rep.test=(2019, 2020) +#rep.test:score=5 ]
            $node.data.set(woot, bad)
        ''')
        await core.nodes('''
            [ inet:url=http://exists.com/y +#rep.test=(2022, 2023) +#rep.test:score=7 +#existing ]
            $node.data.set(woot, good)
        ''')

        # References to nodes which are quarantined, so the migration has to clear
        # the scalar reference and quarantine the read-only comp along with them.
        await core.nodes('[ media:news=* :title="queued ref" :url="c:////spam////eggs" ]')
        await core.nodes('[ inet:urlredir=("c:////spam////eggs", https://good.com/x) ]')
        await core.nodes('[ media:news=* :title="noscheme ref" :url="//www.example.com/submit?url=https://example.org/x" ]')

        # A bad node and a tag on an existing bad node in a forked view, so the
        # migration covers more than one layer, including a layer which holds no
        # primary value for the node it edits.
        fork = await core.callStorm('''
            $view = $lib.view.get().fork()
            $view.set(name, fork00)
            return($view.iden)
        ''')
        await core.nodes('[ inet:url="https:////fork.com/x" ]', opts={'view': fork})
        await core.nodes('''
            inet:url="http:////foo.com/x"
            [ +#fork.only ]
            $node.data.set(forkdata, yep)
        ''', opts={'view': fork})

        # A bad node in a layer which is then made read only. Model migrations
        # run in migration mode, so they must still repair it.
        roview = await core.callStorm('''
            $layr = $lib.layer.add()
            $view = $lib.view.add(($layr.iden,))
            $view.set(name, roview)
            return($view.iden)
        ''')
        await core.nodes('[ inet:url="https:////ro.com/x" +#ro.tag ]', opts={'view': roview})
        await core.callStorm('''
            $view = $lib.view.get($roview)
            $lib.layer.get($view.layers.0.iden).set(readonly, $lib.true)
        ''', opts={'vars': {'roview': roview}})

    s_backup.backup(tmpdir, modldir)

    # Remove the expanded working copy; only the compact backup should remain.
    shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    asyncio.run(main())
