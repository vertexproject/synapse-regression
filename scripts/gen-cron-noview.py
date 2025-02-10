import shutil
import asyncio

import synapse.exc as s_exc
import synapse.cortex as s_cortex

import synapse.lib.version as s_version

import synapse.tools.backup as s_backup

async def main():

    maxver = (2, 197, 0)
    if s_version.version > maxver:
        verstr = '.'.join(map(str, maxver))
        mesg = f'This regression cortex MUST be generated with a cortex LTE {verstr}, not {s_version.verstring}.'
        raise s_exc.BadVersion(mesg=mesg, curv=s_version.verstring, maxver=maxver)

    name = 'cron-noview'
    tmpdir = f'/tmp/v/{name}'
    modldir = f'cortexes/{name}'

    shutil.rmtree(tmpdir, ignore_errors=True)
    shutil.rmtree(modldir, ignore_errors=True)

    async with await s_cortex.Cortex.anit(tmpdir) as core:

        viewiden = await core.callStorm('return($lib.view.get().fork().iden)')

        opts = {'view': viewiden}
        normcron = await core.callStorm('$lib.cron.add(hour=1, query="$foo=ok")', opts=opts)

        # cron user with a default view set
        user1 = await core.addUser(f'user1')
        user1iden = user1.get('iden')
        await core.callStorm('$lib.auth.users.byname(user1).addRule(((true), (cron, add)))')
        await core.callStorm('$lib.auth.users.byname(user1).addRule(((true), (view, read)))')
        await core.callStorm(f'$lib.auth.users.byname(user1).profile."cortex:view" = {viewiden}')

        opts = {'user': user1iden, 'view': core.view.iden}
        q = '''
        $cron = $lib.cron.add(hour=1, query="$foo=userview")
        $lib.cron.move($cron.iden, (null))
        '''
        await core.callStorm(q, opts=opts)

        # cron user with no default view set
        user2 = await core.addUser(f'user2')
        user2iden = user2.get('iden')
        await core.callStorm('$lib.auth.users.byname(user2).addRule(((true), (cron, add)))')
        await core.callStorm('$lib.auth.users.byname(user2).addRule(((true), (view, read)))')

        opts = {'user': user2iden, 'view': viewiden}
        q = '''
        $cron = $lib.cron.add(hour=1, query="$foo=coreview")
        $lib.cron.move($cron.iden, (null))
        '''
        await core.callStorm(q, opts=opts)

        # cron user which has been deleted
        user3 = await core.addUser(f'user3')
        user3iden = user3.get('iden')
        await core.callStorm('$lib.auth.users.byname(user3).addRule(((true), (cron, add)))')
        await core.callStorm('$lib.auth.users.byname(user3).addRule(((true), (view, read)))')

        opts = {'user': user3iden, 'view': viewiden}
        q = '''
        $cron = $lib.cron.add(hour=1, query="$foo=noview")
        $lib.cron.move($cron.iden, (null))
        '''
        await core.callStorm(q, opts=opts)
        await core.delUser(user3iden)

    s_backup.backup(tmpdir, modldir)

if __name__ == '__main__':
    asyncio.run(main())
