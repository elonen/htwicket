<?php
// HTWicket demo backend: show what the protected app actually received —
// the X-Remote-User-* headers nginx injected, and the session-JWT claims.
function b64url($s) {
    return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4));
}
$headers = getallheaders();
ksort($headers);
$claims = [];
if (!empty($_COOKIE['htwicket_session'])) {
    $parts = explode('.', $_COOKIE['htwicket_session']);
    if (count($parts) === 3) {
        $claims = json_decode(b64url($parts[1]), true) ?: ['(could not decode payload)' => ''];
    }
}
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html><meta charset=utf-8><title>HTWicket demo app</title>
<style>
 body{font:14px/1.5 system-ui,sans-serif;margin:2rem;max-width:48rem}
 h1{font-size:1.3rem} h2{font-size:1rem;margin-top:1.5rem}
 table{border-collapse:collapse;width:100%}
 td,th{border:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}
 code{background:#f4f4f4;padding:0 .2rem} .hl td:first-child{font-weight:600}
</style>
<h1>Protected app — what the backend received</h1>
<p>You reached this page only because HTWicket's <code>/auth</code> returned 200.
   <a href="/htwicket/account">account</a> ·
   <a href="/htwicket/admin">admin</a> ·
   <a href="/htwicket/logout">logout</a></p>

<h2>Request headers <small>(X-Remote-User-* are injected by nginx from HTWicket)</small></h2>
<table>
<tr><th>Header</th><th>Value</th></tr>
<?php foreach ($headers as $k => $v): $hl = stripos($k, 'X-Remote-User-') === 0; ?>
<tr<?= $hl ? ' class=hl' : '' ?>><td><?= htmlspecialchars($k) ?></td><td><?= htmlspecialchars($v) ?></td></tr>
<?php endforeach ?>
</table>

<h2>Session JWT claims <small>(decoded from the <code>htwicket_session</code> cookie)</small></h2>
<?php if ($claims): ?>
<table>
<tr><th>Claim</th><th>Value</th></tr>
<?php foreach ($claims as $k => $v): ?>
<tr><td><?= htmlspecialchars($k) ?></td><td><?= htmlspecialchars(is_scalar($v) ? (string) $v : json_encode($v)) ?></td></tr>
<?php endforeach ?>
</table>
<?php else: ?>
<p><em>No session cookie — this is a Basic-auth request, or you are not logged in.</em></p>
<?php endif ?>
