import { Hono } from 'hono';
import { serveStatic } from 'hono/bun';
import { Configuration, CoreApi } from '@goauthentik/api';
import { oidcAuthMiddleware, getAuth, revokeSession, processOAuthCallback } from '@hono/oidc-auth';
import { resolveAcceptLanguage } from 'resolve-accept-language';

import { promises as fs } from 'fs';
import { createHash } from 'crypto';

import { i18n } from './i18n.js';

const ADMIN_TOKEN = process.env.AUTHENTIK_ADMIN_TOKEN;
const PASSWORD_CHECK_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$/;
const app = new Hono();

const coreApi = new CoreApi(new Configuration({
  basePath: process.env.AUTHENTIK_BASE_PATH,
  accessToken: ADMIN_TOKEN
}));

// Middleware setup
app.use('/static/*', serveStatic({ root: './' }));

// Locale and header middleware
app.use(async (c, next) => {

  if (c.req.path.startsWith('/static/')) return await next();

  const al = (c.req.query('lang') || c.req.header('Accept-Language')) || 'en-US';
  const locale = resolveAcceptLanguage(al, [ 'en-US', 'zh-CN', 'zh-TW', 'ja-JP' ], 'en-US', { returnMatchType: false });
  c.set('_locale', locale);

  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Download-Options': 'noopen',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-store, no-cache'
  };
  Object.entries(headers).forEach(([key, value]) => c.header(key, value));

  return await next();
});

const oidcAuth = oidcAuthMiddleware();
app.use(async (c, next) => {
  if (c.req.path === '/' || c.req.path.startsWith('/static/')) return await next();
  return await oidcAuth(c, next);
});

function renderHtml(html, locale, data) {
  return html.replaceAll(/\${(.*?)}/g, (_, expr) => {
    try {
        let intro = `const locale='${locale||'en-US'}';const i18n=JSON.parse(${JSON.stringify(JSON.stringify(i18n))});const i=s=>i18n['${locale}']?i18n['${locale}'][s]||s:s;`;
        if (data) intro += `const data=JSON.parse(${JSON.stringify(JSON.stringify(data))});`;
        return eval(intro + expr);
    } catch (error) {
        console.error(`Error evaluating expression: ${expr}`, error);
        return '';
    }
  });
}

let HTML_FRAME, HTML_INDEX, HTML_CHANGEPASSWORD = '';
async function loadHtml() {
  HTML_FRAME = (await fs.readFile('./templates/frame.html')).toString();
  HTML_INDEX = (await fs.readFile('./templates/index.html')).toString();
  HTML_CHANGEPASSWORD = (await fs.readFile('./templates/changePassword.html')).toString();
}
loadHtml();

function getHtml(children) {
  return HTML_FRAME.replace('<!-- !!children!! -->', children);
}

async function getUserById(userId) {
  return (await coreApi.coreUsersRetrieve({ id: userId })) || null;
}

async function updateWifiPassword(user, newPassword) {
  const newAttributes = {
    ...user.attributes
  };
  newAttributes.wifiPassword = newPassword;
  const updatedUser = await coreApi.coreUsersPartialUpdate({
    id: Number(user.pk),
    patchedUserRequest: {
      attributes: newAttributes
    }
  });
  return updatedUser && updatedUser.attributes && newPassword === updatedUser.attributes.wifiPassword
}

function sha256(message) {
  const hash = createHash('sha256');
  hash.update(message);
  return hash.digest('hex');
}


app.get('/', async c => {
  return c.html(renderHtml(getHtml(HTML_INDEX), c.var._locale));
});

app.get('/logout', async c => {
  await revokeSession(c);
  return c.redirect('/');
});

app.get('/callback', async c => {
  return processOAuthCallback(c);
});

async function sessionGetUser(c) {
  const auth = await getAuth(c);
  if (!auth) return null;

  const userId = Number(auth.sub);
  if (isNaN(userId)) {
    await revokeSession(c);
    return null;
  }

  const user = await getUserById(userId);
  if (!user) await revokeSession(c);
  return user;
}

app.get('/changePassword', async c => {
  const user = await sessionGetUser(c);
  if (!user) return c.redirect('/');

  user.emailHashed = sha256(user.email ?? "localhost@localdomain");
  return c.html(renderHtml(getHtml(HTML_CHANGEPASSWORD), c.var._locale, user));
});

app.post('/changePassword', async c => {
  let user = await sessionGetUser(c);
  if (!user) return c.redirect('/');

  const body = await c.req.parseBody();
  let errorMessage = '';
  if (!body || !body.newPassword || !PASSWORD_CHECK_REGEX.test(body.newPassword)) {
    errorMessage = i18n[c.var._locale]['Your new password does not satisfy at least one rule.'];
  } else if (!await updateWifiPassword(user, body.newPassword)) {
    errorMessage = i18n[c.var._locale]['Cannot change your password.'];
  } else {
    errorMessage = i18n[c.var._locale]['Thank you. Your password has been changed.'];
  }

  user = await sessionGetUser(c);
  if (!user) return c.redirect('/');

  user._errorMessage = errorMessage;
  user.emailHashed = sha256(user.email ?? "localhost@localdomain");
  return c.html(renderHtml(getHtml(HTML_CHANGEPASSWORD), c.var._locale, user));
});

export default {
  hostname: process.env.LISTEN_HOSTNAME,
  port: process.env.LISTEN_PORT,
  certFile: process.env.TLS_CERT_FILE,
  keyFile: process.env.TLS_KEY_FILE,
  fetch: app.fetch,
};
