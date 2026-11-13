import { randomBytes } from 'node:crypto';
import { get, put } from '@vercel/blob';

const LIMIT = 600000; // Characters. Keep reports below Vercel's request-body limit.
const ID_RE = /^[a-zA-Z0-9_-]{24}$/;

function reply(res, code, data) {
  res.status(code).setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  return res.json(data);
}

function validText(s) {
  return typeof s === 'string' && s.length <= LIMIT;
}

async function fetchPaste(id) {
  if (!ID_RE.test(id)) return null;
  const result = await get('pastes/' + id + '.json', {
    access: 'private',
    useCache: false
  });
  if (!result || result.statusCode !== 200 || !result.stream) return null;
  return JSON.parse(await new Response(result.stream).text());
}

async function savePaste(id, data) {
  await put('pastes/' + id + '.json', JSON.stringify(data), {
    access: 'private',
    contentType: 'application/json',
    addRandomSuffix: false,
    allowOverwrite: true
  });
}

export default async function handler(req, res) {
  if (!process.env.BLOB_READ_WRITE_TOKEN) {
    return reply(res, 503, { error: 'Storage is not connected yet.' });
  }

  try {
    if (req.method === 'GET') {
      const id = String(req.query?.id || '');
      if (!ID_RE.test(id)) return reply(res, 400, { error: 'Invalid report ID.' });
      const paste = await fetchPaste(id);
      if (!paste) return reply(res, 404, { error: 'Report not found.' });
      return reply(res, 200, paste);
    }

    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
      if (!validText(body.content)) return reply(res, 400, { error: 'Paste must be text under 600,000 characters.' });
      if (typeof body.title !== 'string' || body.title.trim().length > 90) {
        return reply(res, 400, { error: 'Title must be 90 characters or fewer.' });
      }
      const now = new Date().toISOString();
      const id = randomBytes(18).toString('base64url');
      const paste = {
        id,
        title: body.title.trim() || 'Untitled report',
        content: body.content,
        createdAt: now,
        updatedAt: now,
        version: 1
      };
      await savePaste(id, paste);
      return reply(res, 201, paste);
    }

    if (req.method === 'PUT') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body || {};
      const id = String(body.id || '');
      if (!ID_RE.test(id)) return reply(res, 400, { error: 'Invalid report ID.' });
      if (!validText(body.content)) return reply(res, 400, { error: 'Paste must be text under 600,000 characters.' });
      if (typeof body.title !== 'string' || body.title.trim().length > 90) {
        return reply(res, 400, { error: 'Title must be 90 characters or fewer.' });
      }
      const previous = await fetchPaste(id);
      if (!previous) return reply(res, 404, { error: 'Report not found.' });
      if (!Number.isInteger(body.version) || body.version !== previous.version) {
        return reply(res, 409, {
          error: 'Another editor saved a newer version. Reload it before saving your changes.',
          latestVersion: previous.version
        });
      }
      const paste = {
        ...previous,
        title: body.title.trim() || 'Untitled report',
        content: body.content,
        updatedAt: new Date().toISOString(),
        version: previous.version + 1
      };
      await savePaste(id, paste);
      return reply(res, 200, paste);
    }
    res.setHeader('Allow', 'GET, POST, PUT');
    return reply(res, 405, { error: 'Method not allowed.' });
  } catch (err) {
    // The SDK may throw a 404 rather than return null for nonexistent blobs.
    if (err?.status === 404 || err?.statusCode === 404 || err?.name === 'BlobNotFoundError') {
      return reply(res, 404, { error: 'Report not found.' });
    }
    console.error('Paste API failure:', err?.message || err);
    return reply(res, err instanceof SyntaxError ? 400 : 500, {
      error: err instanceof SyntaxError ? 'Invalid JSON request.' : 'Storage request failed. Please try again.'
    });
  }
}
