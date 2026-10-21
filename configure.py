"""Run inside the remote release folder after its Supabase project is ready."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import re
from urllib.parse import urlparse

p = argparse.ArgumentParser()
p.add_argument('--project-url', required=True)
p.add_argument('--publishable-key', required=True, help='Public publishable/anon key only')
p.add_argument('--admin-email', required=True)
a = p.parse_args()
u = urlparse(a.project_url.rstrip('/'))
assert u.scheme == 'https' and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in ('', '/'), 'Use the HTTPS project root URL'
key = a.publishable_key.strip()
if key.startswith('sb_publishable_'):
    pass
else:
    try:
        segment = key.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))
        assert claims.get('role') == 'anon'
    except Exception:
        raise SystemExit('Only a publishable key or legacy anon key may be placed in a web page')
assert re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', a.admin_email), 'Enter the registered administrator email'
root = Path(__file__).resolve().parent
cfg = json.dumps({'url': a.project_url.rstrip('/'), 'publishableKey': key, 'guestEnabled': True, 'apiVersion': 1}, ensure_ascii=True).replace('<', '\\u003c')
for name in ['index.html', 'admin.html']:
    path = root / name
    text = path.read_text()
    pattern = r'(<script type="application/json" id="sqAccountConfig">).*?(</script>)'
    assert len(re.findall(pattern, text, re.S)) == 1
    text = re.sub(pattern, lambda m: m[1] + cfg + m[2], text, flags=re.S)
    path.write_text(text)
email = a.admin_email.replace("'", "''")
tag = 'sq_setup_' + hashlib.sha256(email.encode()).hexdigest()[:20]
while '$' + tag + '$' in email:
    tag += '_x'
sql = """-- Execute only as the project owner after this email has registered.
begin;
do $%s$
declare uid uuid;
begin
 select id into strict uid from auth.users where lower(email)=lower('%s');
 insert into sq_private.admins(user_id) values(uid) on conflict(user_id) do nothing;
end $%s$;
commit;
""" % (tag, email, tag)
(root / '02-set-admin.sql').write_text(sql)
release = root.parent / 'SQ开的餐厅-v1.2.0.html'
if root.name == 'SQ开的餐厅-v1.2.0-账号管理' and release.exists():
    release.write_bytes((root / 'index.html').read_bytes())
manifest_path = root.parent / '.session/v120_release_manifest.json'
if manifest_path.exists():
    manifest = json.loads(manifest_path.read_text())
    manifest.update({'configured': True, 'sha256': hashlib.sha256((root / 'index.html').read_bytes()).hexdigest(), 'adminSha256': hashlib.sha256((root / 'admin.html').read_bytes()).hexdigest()})
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
print('Public configuration written. Run 02-set-admin.sql as project owner; no secret key was requested.')
