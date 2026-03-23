import 'dotenv/config';
import express from 'express';
import { WebSocketServer, WebSocket } from 'ws';
import { createServer } from 'http';
import crypto from 'crypto';

const PORT = process.env.PORT || 3001;
const CLIENT_ID = process.env.ZOOM_CLIENT_ID || '';
const CLIENT_SECRET = process.env.ZOOM_CLIENT_SECRET || '';
const WEBHOOK_SECRET = process.env.ZOOM_WEBHOOK_SECRET_TOKEN || '';

const app = express();
app.use(express.raw({ type: '*/*', limit: '10mb' }));

const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer });

const browserClients = new Set();

wss.on('connection', (ws, req) => {
  if ((req.url || '/') === '/stream') {
    browserClients.add(ws);
    ws.on('close', () => browserClients.delete(ws));
    ws.on('error', () => browserClients.delete(ws));
  }
});

function broadcastFrame(base64Frame) {
  for (const client of browserClients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(base64Frame);
    }
  }
}

function makeSignature(meetingUuid, streamId) {
  return crypto
    .createHmac('sha256', CLIENT_SECRET)
    .update(CLIENT_ID + meetingUuid + streamId)
    .digest('hex');
}

function verifyWebhookSignature(body, signature) {
  if (!WEBHOOK_SECRET) return true;
  const hash = crypto.createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
  return hash === signature;
}

app.post('/', (req, res) => {
  const signature = req.headers['x-zm-signature'] || '';
  if (!verifyWebhookSignature(req.body, signature)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  let event;
  try {
    event = JSON.parse(req.body.toString());
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  if (event.event === 'endpoint.url_validation') {
    const encrypted = crypto
      .createHmac('sha256', WEBHOOK_SECRET)
      .update(event.payload.plainToken)
      .digest('hex');
    return res.json({ plainToken: event.payload.plainToken, encryptedToken: encrypted });
  }

  if (event.event === 'meeting.rtms_started' || event.event === 'meeting.rtms_stream_started') {
    const payload = event.payload?.object || event.payload || {};
    const serverUrls = payload.server_urls || payload.operator?.server_urls;
    const meetingUuid = payload.meeting_uuid || payload.uuid || payload.operator?.meeting_uuid;
    const streamId = payload.rtms_stream_id || payload.stream_id || payload.operator?.stream_id;

    if (serverUrls && meetingUuid && streamId) {
      connectSignaling(serverUrls, meetingUuid, streamId);
    } else {
      console.warn('RTMS event missing required fields:', JSON.stringify(payload));
    }
  }

  res.json({ received: true });
});

app.get('/health', (_req, res) => res.json({ ok: true, clients: browserClients.size }));

function connectSignaling(serverUrls, meetingUuid, streamId) {
  const urls = Array.isArray(serverUrls) ? serverUrls : [serverUrls];
  const url = urls[0];

  console.log(`[RTMS] Connecting to signaling: ${url}`);

  const sigWs = new WebSocket(url);

  sigWs.on('open', () => {
    const sig = makeSignature(meetingUuid, streamId);
    const req = {
      msg_type: 'SIGNALING_HAND_SHAKE_REQ',
      protocol_version: 1,
      meeting_uuid: meetingUuid,
      rtms_stream_id: streamId,
      signature: sig,
    };
    console.log('[RTMS] Sending SIGNALING_HAND_SHAKE_REQ');
    sigWs.send(JSON.stringify(req));
  });

  sigWs.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    if (msg.msg_type === 'SIGNALING_HAND_SHAKE_RESP') {
      if (msg.status !== 'STATUS_OK') {
        console.error('[RTMS] Signaling handshake failed:', msg.status);
        sigWs.close();
        return;
      }
      console.log('[RTMS] Signaling handshake OK');
      const mediaUrls = msg.media_urls || {};
      const videoUrl = mediaUrls.video || mediaUrls.all;
      if (videoUrl) {
        connectMedia(videoUrl, meetingUuid, streamId);
      } else {
        console.error('[RTMS] No video URL in signaling response');
      }
    }

    if (msg.msg_type === 'KEEP_ALIVE_REQ') {
      sigWs.send(JSON.stringify({ msg_type: 'KEEP_ALIVE_RESP', timestamp: msg.timestamp }));
    }
  });

  sigWs.on('error', (err) => console.error('[RTMS] Signaling WS error:', err.message));
  sigWs.on('close', () => console.log('[RTMS] Signaling WS closed'));
}

function connectMedia(url, meetingUuid, streamId) {
  console.log(`[RTMS] Connecting to media: ${url}`);

  const mediaWs = new WebSocket(url);

  mediaWs.on('open', () => {
    const sig = makeSignature(meetingUuid, streamId);
    const req = {
      msg_type: 'DATA_HAND_SHAKE_REQ',
      protocol_version: 1,
      meeting_uuid: meetingUuid,
      rtms_stream_id: streamId,
      signature: sig,
      payload_encryption: false,
    };
    console.log('[RTMS] Sending DATA_HAND_SHAKE_REQ');
    mediaWs.send(JSON.stringify(req));
  });

  mediaWs.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    if (msg.msg_type === 'DATA_HAND_SHAKE_RESP') {
      if (msg.status !== 'STATUS_OK') {
        console.error('[RTMS] Media handshake failed:', msg.status, JSON.stringify(msg));
        mediaWs.close();
        return;
      }
      console.log('[RTMS] Media handshake OK — video stream active. Full resp:', JSON.stringify(msg));
    }

    if (msg.msg_type === 'MEDIA_DATA_VIDEO' && msg.data) {
      const byteLen = Math.round((msg.data.length * 3) / 4);
      console.log(`[RTMS] VIDEO frame received — base64 len=${msg.data.length} (~${byteLen} bytes), clients=${browserClients.size}`);
      broadcastFrame(msg.data);
    }

    if (msg.msg_type === 'KEEP_ALIVE_REQ') {
      mediaWs.send(JSON.stringify({ msg_type: 'KEEP_ALIVE_RESP', timestamp: msg.timestamp }));
    }

    if (msg.msg_type === 'SESSION_STATE_UPDATE') {
      console.log('[RTMS] Session state:', msg.state);
      if (msg.state === 'STOPPED') mediaWs.close();
    }

    if (!['DATA_HAND_SHAKE_RESP', 'MEDIA_DATA_VIDEO', 'KEEP_ALIVE_REQ', 'SESSION_STATE_UPDATE'].includes(msg.msg_type)) {
      console.log('[RTMS] Unknown media msg_type:', msg.msg_type, JSON.stringify(msg).slice(0, 200));
    }
  });

  mediaWs.on('error', (err) => console.error('[RTMS] Media WS error:', err.message));
  mediaWs.on('close', () => console.log('[RTMS] Media WS closed'));
}

httpServer.listen(PORT, () => {
  console.log(`RTMS relay server listening on port ${PORT}`);
  console.log(`  Webhook:     POST /`);
  console.log(`  Browser WS:  ws://localhost:${PORT}/stream`);
  console.log(`  Health:      GET  /health`);
});
